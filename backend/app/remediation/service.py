"""RemediationService: post-approval, human-confirmed fix workflow.

Authorization model (all enforced here, never in the frontend):

* proposal generation requires an **approved** approval request for the
  finding (action ``remediation``);
* applying a proposal requires the explicit ``confirm=true`` flag - the
  approval alone never modifies source code;
* the patch is applied to the private workspace copy of the repository only
  (``workspace/projects/<id>/repo/``), never to the original source;
* ``verify`` re-runs the deterministic scanner against the current snapshot
  and checks whether the same finding id is still produced - the result is
  ``verified`` or ``still_present``, never guessed.

The finding's owning project is always resolved through the explicit scan
lineage (finding -> scan runs -> project); it is never inferred from file
paths or timestamps.
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from app.approval.models import ApprovalRequest
from app.approval.store import get_approval_store
from app.config import Settings
from app.db.models import Project
from app.remediation.models import RemediationProposal, RemediationRecord
from app.remediation.patches import (
    PatchError,
    apply_proposal,
    build_proposal,
)
from app.remediation.store import get_remediation_store
from app.scan.run_store import get_scan_run_store
from app.scan.service import ScanService
from app.validate.store import get_finding_store

logger = logging.getLogger(__name__)

#: Demo reviewer identity (same documented demo identity as approvals).
DEMO_APPLIED_BY = "security-analyst"


class RemediationGateError(Exception):
    """Raised when the remediation workflow is invoked out of order."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RemediationService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # ----------------------------------------------------------------- gates

    def _require_approved_approval(self, finding_id: str) -> ApprovalRequest:
        approval = get_approval_store().find_for_finding(finding_id)
        if approval is None:
            raise RemediationGateError(
                f"finding {finding_id} has no approval request; "
                "remediation requires an approved approval"
            )
        if approval.action != "remediation":
            raise RemediationGateError(
                f"approval {approval.id} authorizes action "
                f"'{approval.action}', not remediation"
            )
        if approval.status != "approved":
            raise RemediationGateError(
                f"approval {approval.id} is '{approval.status}'; "
                "remediation requires an approved approval"
            )
        return approval

    def _project_for_finding(self, finding_id: str, session_factory) -> Project:
        """Resolve the owning project exclusively via explicit scan lineage."""
        run_store = get_scan_run_store()
        project_ids = sorted(
            {run.project_id for run in run_store.runs_for_finding(finding_id)}
        )
        if len(project_ids) != 1:
            raise RemediationGateError(
                f"finding {finding_id} has {len(project_ids)} owning "
                "projects in its scan lineage; cannot resolve a workspace"
            )
        with session_factory() as session:
            project = session.get(Project, project_ids[0])
        if project is None:
            raise RemediationGateError(
                f"owning project {project_ids[0]} for finding {finding_id} "
                "no longer exists"
            )
        return project

    def _workspace_repo_dir(self, project: Project) -> Path:
        workspace = self._settings.workspace_dir.resolve()
        repo_dir = (Path(project.snapshot_path) / "repo").resolve()
        if not repo_dir.is_relative_to(workspace):
            raise RemediationGateError(
                "repository workspace is outside the application workspace"
            )
        return repo_dir

    def _read_source(self, project: Project, proposal: RemediationProposal) -> str:
        repo_dir = self._workspace_repo_dir(project)
        file_path = (repo_dir / proposal.file).resolve()
        if not file_path.is_relative_to(repo_dir):
            raise RemediationGateError(
                f"patch target {proposal.file} escapes the repository workspace"
            )
        return file_path.read_text(encoding="utf-8", errors="replace")

    # --------------------------------------------------------------- actions

    def propose(self, finding_id: str, session_factory) -> RemediationRecord:
        """Generate a deterministic proposal (requires an approved approval)."""
        store = get_remediation_store()
        finding = get_finding_store().get(finding_id)
        if finding is None:
            raise RemediationGateError(f"finding not found: {finding_id}")
        approval = self._require_approved_approval(finding_id)
        project = self._project_for_finding(finding_id, session_factory)
        repo_dir = self._workspace_repo_dir(project)
        file_path = (repo_dir / finding.sink.file).resolve()
        if not file_path.is_relative_to(repo_dir):
            raise RemediationGateError(
                f"finding source {finding.sink.file} escapes the repository workspace"
            )
        source = file_path.read_text(encoding="utf-8", errors="replace")
        proposal = build_proposal(finding, source)
        record = store.get(finding_id)
        if record is None:
            record = RemediationRecord(
                finding_id=finding_id,
                approval_id=approval.id,
                status=(
                    "no_fix_available"
                    if proposal.strategy == "no_automatic_fix"
                    else "proposed"
                ),
                proposal=proposal,
                created_at=_utcnow(),
            )
        else:
            record = record.model_copy(
                update={
                    "approval_id": approval.id,
                    "proposal": proposal,
                    "status": (
                        "no_fix_available"
                        if proposal.strategy == "no_automatic_fix"
                        else "proposed"
                    ),
                    "error": None,
                }
            )
        store.record(record)
        logger.info(
            "remediation proposal for %s: strategy=%s file=%s:%d",
            finding_id, proposal.strategy, proposal.file, proposal.line,
        )
        return record

    def apply(
        self, finding_id: str, *, confirmed: bool, session_factory
    ) -> RemediationRecord:
        """Apply an approved proposal - the ONLY mutation of source code.

        ``confirmed`` must be true: the human explicitly confirmed the
        proposed diff. The approval alone never modifies anything.
        """
        store = get_remediation_store()
        record = store.get(finding_id)
        if record is None or record.proposal is None:
            raise RemediationGateError(
                f"no remediation proposal for finding {finding_id}; "
                "generate one before applying"
            )
        if record.status == "no_fix_available":
            raise RemediationGateError(
                "no automatic fix is available for this finding; "
                "manual remediation is required"
            )
        if record.status == "applied":
            raise RemediationGateError(
                f"remediation for finding {finding_id} was already applied"
            )
        self._require_approved_approval(finding_id)
        if not confirmed:
            raise RemediationGateError(
                "fix application requires explicit human confirmation "
                "(confirm=true)"
            )
        project = self._project_for_finding(finding_id, session_factory)
        repo_dir = self._workspace_repo_dir(project)
        file_path = (repo_dir / record.proposal.file).resolve()
        if not file_path.is_relative_to(repo_dir):
            raise RemediationGateError(
                f"patch target {record.proposal.file} escapes the repository workspace"
            )
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            patched = apply_proposal(record.proposal, source)
        except PatchError as exc:
            record = record.model_copy(
                update={"status": "error", "error": str(exc)}
            )
            store.record(record)
            raise RemediationGateError(str(exc)) from exc
        file_path.write_text(patched, encoding="utf-8")
        record = record.model_copy(
            update={
                "status": "applied",
                "applied_at": _utcnow(),
                "applied_by": DEMO_APPLIED_BY,
                "error": None,
            }
        )
        store.record(record)
        logger.info(
            "remediation applied: finding=%s file=%s:%d strategy=%s",
            finding_id, record.proposal.file, record.proposal.line,
            record.proposal.strategy,
        )
        return record

    def verify(self, finding_id: str, session_factory) -> RemediationRecord:
        """Re-run the scanner on the current snapshot; check finding identity.

        The result reflects exactly what a fresh scan of the current
        snapshot would produce - it is never inferred from the old finding
        or from timestamps.
        """
        store = get_remediation_store()
        record = store.get(finding_id)
        if record is None:
            raise RemediationGateError(
                f"no remediation record for finding {finding_id}"
            )
        if record.status not in ("applied", "verified", "still_present"):
            raise RemediationGateError(
                f"remediation for finding {finding_id} is '{record.status}'; "
                "verify requires an applied fix"
            )
        project = self._project_for_finding(finding_id, session_factory)
        code_model = _load_code_model(project)
        report = ScanService().scan(code_model, project_id=project.id)
        still_present = any(f.id == finding_id for f in report.findings)
        verification = "still_present" if still_present else "verified"
        record = record.model_copy(
            update={
                "status": verification,
                "verification": verification,
                "verified_at": _utcnow(),
                "error": None,
            }
        )
        store.record(record)
        logger.info(
            "remediation verify: finding=%s verification=%s",
            finding_id, verification,
        )
        return record


def _load_code_model(project: Project):
    from app.prepare.service import PrepareService

    return PrepareService.load_code_model(Path(project.snapshot_path))