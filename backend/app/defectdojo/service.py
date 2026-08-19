"""DefectDojo service layer.

Orchestrates the creation of DefectDojo findings/tickets from SAST
engine findings.  The service:

1. Translates our CandidateFinding into DefectDojo's finding schema
2. Creates the finding via the real API client
3. Records the ticket locally (in-memory + SQLite backing)
4. Provides sync status for the UI

The service NEVER fabricates DefectDojo responses.  When the server is
unreachable or credentials are wrong, the error is recorded and exposed
to the user.
"""

import hashlib
import logging
from datetime import datetime, timezone

from app.defectdojo.client import (
    DefectDojoClient,
    DefectDojoClientError,
)
from app.defectdojo.config import DefectDojoConfig, get_defectdojo_config
from app.defectdojo.models import (
    DefectDojoConnectionTest,
    DefectDojoFindingCreate,
    DefectDojoFindingResponse,
    DefectDojoSyncResult,
    DefectDojoTicket,
)
from app.scan.models import CandidateFinding

logger = logging.getLogger(__name__)

#: Severity mapping from our scanner to DefectDojo numerical severity.
SEVERITY_MAP = {
    "critical": (1, "Critical"),
    "high": (2, "High"),
    "medium": (3, "Medium"),
    "low": (4, "Low"),
    "info": (5, "Info"),
}


def _ticket_id(finding_id: str) -> str:
    """Deterministic ticket key for a finding."""
    return hashlib.sha256(f"defectdojo|{finding_id}".encode()).hexdigest()[:32]


# ──────────────────────────────────────── in-memory ticket store

_TICKETS: dict[str, DefectDojoTicket] = {}  # key = our finding_id
_factory = None


def set_defectdojo_store_factory(factory) -> None:
    """Rehydrate tickets from the database (lifespan)."""
    from app.db.models import DefectDojoTicketRow
    from app.db.persistence import db_load_all

    global _factory
    _factory = factory
    _TICKETS.clear()
    for key, ticket in db_load_all(factory, DefectDojoTicketRow, DefectDojoTicket, "finding_id"):
        _TICKETS[key] = ticket


def get_ticket(finding_id: str) -> DefectDojoTicket | None:
    return _TICKETS.get(finding_id)


def all_tickets() -> list[DefectDojoTicket]:
    return list(_TICKETS.values())


def _persist_ticket(ticket: DefectDojoTicket) -> None:
    from app.db.models import DefectDojoTicketRow
    from app.db.persistence import db_upsert

    _TICKETS[ticket.finding_id] = ticket
    db_upsert(_factory, DefectDojoTicketRow, "finding_id", ticket.finding_id, ticket)


# ──────────────────────────────────────── service class


class DefectDojoService:
    """Service for creating and managing DefectDojo findings/tickets."""

    def __init__(self, config: DefectDojoConfig | None = None) -> None:
        self._config = config or get_defectdojo_config()
        self._client = DefectDojoClient(self._config)

    @property
    def client(self) -> DefectDojoClient:
        return self._client

    @property
    def is_enabled(self) -> bool:
        return self._client.is_enabled

    # ────────────────────────────────── connection test

    def test_connection(self) -> DefectDojoConnectionTest:
        """Test connectivity to DefectDojo."""
        return self._client.test_connection()

    # ────────────────────────────────── finding creation

    def _to_defectdojo_finding(
        self, finding: CandidateFinding
    ) -> DefectDojoFindingCreate:
        """Translate a CandidateFinding into a DefectDojo finding payload."""
        num_severity, severity_label = SEVERITY_MAP.get(
            finding.severity, (3, "Medium")
        )

        taint_summary = " → ".join(
            f"{step.step_type}({step.file}:{step.line})"
            for step in finding.taint_path
        )

        description = (
            f"**Vulnerability Type:** {finding.vulnerability_type}\n"
            f"**Scanner Confidence:** {finding.confidence:.2f}\n"
            f"**Source:** {finding.source.file}:{finding.source.line} "
            f"({finding.source.kind})\n"
            f"**Sink:** {finding.sink.file}:{finding.sink.line} "
            f"({finding.sink.kind})\n"
            f"**Taint Path:** {taint_summary}\n"
            f"**Source Snippet:** `{finding.source.snippet}`\n"
            f"**Sink Snippet:** `{finding.sink.snippet}`\n"
        )

        mitigation = self._mitigation_for(finding.vulnerability_type)

        return DefectDojoFindingCreate(
            title=f"{finding.vulnerability_type}: {finding.sink.snippet[:80]}",
            severity=severity_label,
            numerical_severity=num_severity,
            description=description,
            mitigation=mitigation,
            file_path=finding.source.file,
            line=finding.source.line,
            product_id=self._config.product_id,
            engagement_id=self._config.engagement_id,
            test_type_name=self._config.test_type_name,
        )

    @staticmethod
    def _mitigation_for(vuln_type: str) -> str:
        """Return remediation guidance for a vulnerability type."""
        mitigations = {
            "sql_injection": (
                "Use parameterized queries or an ORM. Never construct SQL "
                "strings with user input. Example: "
                "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))"
            ),
            "command_injection": (
                "Avoid shell execution with user input. Use subprocess with "
                "list arguments (shell=False). Example: "
                "subprocess.run(['ls', directory], shell=False)"
            ),
            "ssrf": (
                "Validate and whitelist allowed URLs before making HTTP "
                "requests. Restrict network access to trusted hosts only."
            ),
            "deserialization": (
                "Never deserialize untrusted data with pickle, marshal, or "
                "yaml.load. Use safe alternatives like json.loads() or "
                "yaml.safe_load()."
            ),
        }
        return mitigations.get(vuln_type, "Review and remediate as appropriate.")

    def create_ticket(
        self, finding: CandidateFinding
    ) -> DefectDojoTicket:
        """Create a DefectDojo ticket for a SAST finding.

        Records the ticket locally regardless of whether the DefectDojo
        API call succeeds — the error is captured in the ticket record.
        """
        ticket = DefectDojoTicket(
            finding_id=finding.id,
            status="pending",
            created_at=datetime.now(timezone.utc),
            payload=finding.model_dump(mode="json"),
        )

        if not self.is_enabled:
            ticket.status = "error"
            ticket.error_message = (
                "DefectDojo integration is not enabled. "
                "Configure SAST_DEFECTDOJO_URL, SAST_DEFECTDOJO_API_KEY, "
                "and SAST_DEFECTDOJO_ENABLED=true."
            )
            _persist_ticket(ticket)
            logger.warning(
                "DefectDojo ticket not created (integration disabled): finding=%s",
                finding.id[:12],
            )
            return ticket

        dd_finding = self._to_defectdojo_finding(finding)
        try:
            response = self._client.create_finding(dd_finding)
            ticket.defectdojo_finding_id = response.id
            ticket.defectdojo_url = response.url
            ticket.status = "created"
            ticket.updated_at = datetime.now(timezone.utc)
            logger.info(
                "DefectDojo finding created: id=%d for SAST finding=%s",
                response.id,
                finding.id[:12],
            )
        except DefectDojoClientError as exc:
            ticket.status = "error"
            ticket.error_message = str(exc)
            ticket.updated_at = datetime.now(timezone.utc)
            logger.error(
                "DefectDojo finding creation failed for %s: %s",
                finding.id[:12],
                exc,
            )

        _persist_ticket(ticket)
        return ticket

    # ────────────────────────────────── batch sync

    def sync_findings(
        self, findings: list[CandidateFinding]
    ) -> DefectDojoSyncResult:
        """Sync multiple findings to DefectDojo.

        Creates tickets for findings that don't have one yet.
        Returns a summary of the sync operation.
        """
        created = 0
        errors = 0
        tickets: list[DefectDojoTicket] = []
        error_messages: list[str] = []

        for finding in findings:
            existing = get_ticket(finding.id)
            if existing and existing.status in ("created", "synced"):
                continue  # already synced

            ticket = self.create_ticket(finding)
            tickets.append(ticket)
            if ticket.status in ("created", "synced"):
                created += 1
            else:
                errors += 1
                if ticket.error_message:
                    error_messages.append(ticket.error_message)

        return DefectDojoSyncResult(
            total=len(findings),
            created=created,
            updated=0,
            errors=errors,
            tickets=tickets,
            error_messages=error_messages,
        )

    # ────────────────────────────────── status

    def get_status(self) -> dict:
        """Return the current integration status for the dashboard."""
        config = self._config
        return {
            "enabled": config.enabled,
            "configured": bool(config.url and config.api_key),
            "url": config.url,
            "product_id": config.product_id,
            "engagement_id": config.engagement_id,
            "ticket_count": len(_TICKETS),
            "tickets_with_error": sum(
                1 for t in _TICKETS.values() if t.status == "error"
            ),
        }
