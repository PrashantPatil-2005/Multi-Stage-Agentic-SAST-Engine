"""Risk assessment + SLA tracking + escalation services.

- :class:`RiskService` assesses a finding (optionally with validation and
  proof results) into a deterministic :class:`RiskAssessment`, and can
  assess a deduplication group through its canonical finding.
- :class:`SLAService` creates :class:`SLARecord`\\ s, checks deadlines,
  marks resolutions, and produces an :class:`EscalationEvent` exactly once
  on the active -> breached transition (idempotent on repeated checks).

All operations are pure business logic: no notifications, no network, no
LLM, no repository modification. Timestamps are timezone-aware UTC; naive
datetimes raise ``ValueError``.
"""

import logging
from datetime import datetime, timezone

from app.dedup.models import DeduplicationGroup
from app.prove.models import ProofResult
from app.risk.models import (
    EscalationEvent,
    RiskAssessment,
    SLARecord,
)
from app.risk.policies import SLAPolicy
from app.risk.scoring import RiskPolicy, RiskScorer
from app.scan.models import CandidateFinding
from app.validate.models import ValidationResult

logger = logging.getLogger(__name__)


def _ensure_aware_utc(value: datetime, what: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(
            f"{what} must be a timezone-aware datetime (naive datetimes are not allowed)"
        )
    return value.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RiskService:
    def __init__(self, scorer: RiskScorer | None = None) -> None:
        self._scorer = scorer or RiskScorer(RiskPolicy())

    def assess(
        self,
        finding: CandidateFinding,
        validation: ValidationResult | None = None,
        proof: ProofResult | None = None,
        assessed_at: datetime | None = None,
    ) -> RiskAssessment:
        score, priority, factors = self._scorer.score(finding, validation, proof)
        return RiskAssessment(
            finding_id=finding.id,
            vulnerability_type=finding.vulnerability_type,
            severity=finding.severity,
            risk_score=score,
            priority=priority,
            factors=factors,
            assessed_at=assessed_at or _utcnow(),
        )

    def assess_group(
        self,
        group: DeduplicationGroup,
        validation: ValidationResult | None = None,
        proof: ProofResult | None = None,
        assessed_at: datetime | None = None,
    ) -> RiskAssessment:
        """Assess the canonical finding of a deduplication group.

        The canonical finding represents the deduplicated issue; every group
        member id is preserved on ``related_finding_ids`` for traceability.
        """
        assessment = self.assess(
            group.representative_finding, validation, proof, assessed_at
        )
        return assessment.model_copy(
            update={"related_finding_ids": sorted(group.member_finding_ids)}
        )


class SLAService:
    def __init__(self, policy: SLAPolicy | None = None) -> None:
        self._policy = policy or SLAPolicy()

    @property
    def policy(self) -> SLAPolicy:
        return self._policy

    def create_sla(
        self,
        assessment: RiskAssessment,
        started_at: datetime | None = None,
    ) -> SLARecord:
        started = _ensure_aware_utc(started_at or _utcnow(), "started_at")
        duration = self._policy.duration_for(assessment.priority)
        if duration is None:
            return SLARecord(
                finding_id=assessment.finding_id,
                priority=assessment.priority,
                started_at=started,
                due_at=None,
                status="not_applicable",
            )
        return SLARecord(
            finding_id=assessment.finding_id,
            priority=assessment.priority,
            started_at=started,
            due_at=started + duration,
            status="active",
        )

    def check_sla(
        self,
        record: SLARecord,
        now: datetime | None = None,
    ) -> tuple[SLARecord, EscalationEvent | None]:
        """Evaluate one record against ``now``.

        Transitions only move forward: not_applicable -> active -> breached
        -> resolved. ``breached_at`` and the escalation event are set exactly
        once; repeated checks on an already-breached record return no event.
        """
        now = _ensure_aware_utc(now or _utcnow(), "now")

        if record.status == "resolved":
            return (
                record.model_copy(update={"last_checked_at": now}),
                None,
            )

        if record.due_at is None:
            return (
                record.model_copy(update={"status": "not_applicable", "last_checked_at": now}),
                None,
            )

        if record.status == "breached":
            return (
                record.model_copy(update={"last_checked_at": now}),
                None,
            )

        if now >= record.due_at:
            event = EscalationEvent(
                finding_id=record.finding_id,
                previous_level=record.escalation_level,
                new_level=record.escalation_level + 1,
                reason=(
                    f"SLA breached for {record.priority}: due {record.due_at.isoformat()} "
                    f"exceeded at {now.isoformat()}"
                ),
                created_at=now,
            )
            return (
                record.model_copy(
                    update={
                        "status": "breached",
                        "breached_at": now,
                        "escalation_level": record.escalation_level + 1,
                        "last_checked_at": now,
                    }
                ),
                event,
            )

        return (
            record.model_copy(update={"status": "active", "last_checked_at": now}),
            None,
        )

    def resolve_sla(
        self,
        record: SLARecord,
        resolved_at: datetime | None = None,
    ) -> SLARecord:
        """Mark the SLA resolved (terminal; a resolved SLA never reactivates).

        Repeated calls keep the first ``resolved_at``.
        """
        if record.status == "resolved":
            return record
        now = _ensure_aware_utc(resolved_at or _utcnow(), "resolved_at")
        return record.model_copy(update={"status": "resolved", "resolved_at": now})

    def check_all(
        self,
        records: list[SLARecord],
        now: datetime | None = None,
    ) -> list[tuple[SLARecord, EscalationEvent | None]]:
        return [self.check_sla(record, now) for record in records]


# --------------------------------------------------------------------------
# In-memory stores (same convention as validate/prove/dedup singletons),
# with optional SQLite backing via app/db/persistence.py.
# --------------------------------------------------------------------------

_risk_store: dict[str, RiskAssessment] = {}
_sla_store: dict[str, SLARecord] = {}
_escalation_store: dict[str, list[EscalationEvent]] = {}
_factory = None


def set_risk_store_factory(factory) -> None:
    """Rehydrate risk/SLA/escalation stores from the database (lifespan)."""
    from app.db.models import RiskAssessmentRow, SlaEventRow, SlaRecordRow
    from app.db.persistence import db_load_all

    global _factory
    _factory = factory
    _risk_store.clear()
    _sla_store.clear()
    _escalation_store.clear()
    for key, assessment in db_load_all(
        factory, RiskAssessmentRow, RiskAssessment, "finding_id"
    ):
        _risk_store[key] = assessment
    for key, record in db_load_all(factory, SlaRecordRow, SLARecord, "finding_id"):
        _sla_store[key] = record
    for _, event in db_load_all(factory, SlaEventRow, EscalationEvent, "id"):
        _escalation_store.setdefault(event.finding_id, []).append(event)
    for events in _escalation_store.values():
        events.sort(key=lambda e: e.created_at)


def get_risk_assessment(finding_id: str) -> RiskAssessment | None:
    return _risk_store.get(finding_id)


def record_risk_assessment(assessment: RiskAssessment) -> None:
    from app.db.models import RiskAssessmentRow
    from app.db.persistence import db_upsert

    _risk_store[assessment.finding_id] = assessment
    db_upsert(
        _factory, RiskAssessmentRow, "finding_id", assessment.finding_id, assessment
    )


def get_sla_record(finding_id: str) -> SLARecord | None:
    return _sla_store.get(finding_id)


def record_sla_record(record: SLARecord) -> None:
    from app.db.models import SlaRecordRow
    from app.db.persistence import db_upsert

    _sla_store[record.finding_id] = record
    db_upsert(_factory, SlaRecordRow, "finding_id", record.finding_id, record)


def get_escalation_events(finding_id: str) -> list[EscalationEvent]:
    return list(_escalation_store.get(finding_id, []))


def record_escalation_event(event: EscalationEvent) -> None:
    from app.db.models import SlaEventRow
    from app.db.persistence import db_insert

    _escalation_store.setdefault(event.finding_id, []).append(event)
    db_insert(
        _factory,
        SlaEventRow(
            finding_id=event.finding_id,
            payload=event.model_dump(mode="json"),
        ),
    )


def all_risk_assessments() -> list[RiskAssessment]:
    """Read-only enumeration (used by read/summary endpoints)."""
    return list(_risk_store.values())


def all_sla_records() -> list[SLARecord]:
    """Read-only enumeration (used by read/summary endpoints)."""
    return list(_sla_store.values())


def all_escalation_events() -> list[EscalationEvent]:
    """Read-only enumeration (used by read/summary endpoints)."""
    return [event for events in _escalation_store.values() for event in events]


def remove_finding_state(finding_id: str) -> None:
    """Remove every risk/SLA/escalation record for one finding.

    Used by repository deletion. Idempotent: missing records are fine.
    """
    from app.db.models import RiskAssessmentRow, SlaEventRow, SlaRecordRow
    from app.db.persistence import db_delete

    _risk_store.pop(finding_id, None)
    _sla_store.pop(finding_id, None)
    _escalation_store.pop(finding_id, None)
    db_delete(_factory, RiskAssessmentRow, "finding_id", finding_id)
    db_delete(_factory, SlaRecordRow, "finding_id", finding_id)
    if _factory is None:
        return
    with _factory() as session:
        session.query(SlaEventRow).filter(
            SlaEventRow.finding_id == finding_id
        ).delete()
        session.commit()


def reset_risk_stores() -> None:
    from app.db.models import RiskAssessmentRow, SlaEventRow, SlaRecordRow
    from app.db.persistence import db_delete_all

    _risk_store.clear()
    _sla_store.clear()
    _escalation_store.clear()
    db_delete_all(_factory, RiskAssessmentRow)
    db_delete_all(_factory, SlaRecordRow)
    db_delete_all(_factory, SlaEventRow)