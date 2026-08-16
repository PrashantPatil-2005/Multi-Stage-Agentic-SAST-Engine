"""Scan run orchestrator: executes the scan route's pipeline with lineage.

The scan route (POST /api/projects/{id}/scan) runs synchronously. This
service wraps the existing stage services — it does not reimplement any of
their business logic — and records the durable ScanRun + stage + execution +
finding lineage defined by Phases 14D/14J.

Execution model (matches the route's real behavior):

* every pipeline stage (PREPARE, SCAN, DEDUPLICATE, RISK, SLA, VALIDATE,
  PROVE, APPROVAL) is registered as ``pending`` when the run starts; PREPARE
  is immediately recorded completed (a run only exists for a prepared
  project) and the SCAN stage runs the existing ``ScanService``, registers
  the findings in the finding store, and records explicit finding lineage;
* DEDUPLICATE/RISK/SLA/VALIDATE/PROVE/APPROVAL are separate user-triggered
  endpoints. They stay ``pending`` until a request explicitly carries a
  ``scan_run_id`` context (Phases 14J/14K); such a request records one
  append-only execution of that stage against the run (see
  :func:`record_stage_execution`);
* the run finishes ``completed`` (with real counts from the report) or
  ``failed`` (with the error persisted and the exception re-raised).

Lineage validation (:func:`validate_stage_context`) never infers a scan run
from timestamps, paths or ordering: a stage action is only recorded against
a run whose explicit ``scan_findings`` lineage produces the finding(s).

No fake progress, no fabricated counts, no swallowed exceptions.
"""

import logging
from datetime import datetime, timezone
from uuid import uuid4

from app.core.contracts import CodeModel
from app.scan.models import ScanReport
from app.scan.run_models import (
    STAGE_PREPARE,
    STAGE_SCAN,
    STAGE_NAMES,
    ScanRun,
    ScanStageRun,
)
from app.scan.run_store import get_scan_run_store
from app.scan.service import ScanService
from app.validate.store import get_finding_store

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware_utc(value: datetime) -> datetime:
    """Normalize a possibly-naive datetime to aware UTC (SQLite returns
    Project rows with naive datetimes; run timestamps are always aware)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class StageContextError(Exception):
    """A stage action referenced a scan-run context that does not exist or
    does not produce the target finding(s). Carries an HTTP status + detail
    so routes can surface it without fabricating a different error."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def record_stage_execution(
    scan_run_id: str,
    stage_name: str,
    fn,
    *,
    error_condition=None,
) -> object:
    """Record one explicit execution of a stage against a scan run.

    Sets the stage ``running`` (append-only execution record), invokes
    ``fn``, then marks the stage ``completed`` — or ``failed`` with the
    error persisted and the exception re-raised (never swallowed). Each call
    appends a new execution record, so retrying a failed stage preserves the
    previous attempt's history. Returns ``fn``'s result on success.

    ``error_condition`` is an optional ``callable(result) -> (bool, str)``:
    when it reports ``(True, message)`` the stage is marked ``failed`` with
    ``message`` even though ``fn`` returned normally (used by PROVE, where a
    returned ``ProofResult(status="error")`` is a failed execution, not a
    completed one). The result is still returned to the caller unchanged.
    """
    store = get_scan_run_store()
    now = _utcnow()
    execution_id = uuid4().hex
    store.begin_stage_execution(scan_run_id, stage_name, execution_id, now)
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - stage failure boundary
        logger.exception("stage %s failed on scan run %s", stage_name, scan_run_id)
        store.fail_stage_execution(
            scan_run_id, stage_name, execution_id, _utcnow(), str(exc)
        )
        raise
    if error_condition is not None:
        should_fail, message = error_condition(result)
        if should_fail:
            store.fail_stage_execution(
                scan_run_id, stage_name, execution_id, _utcnow(), message
            )
            return result
    store.complete_stage_execution(scan_run_id, stage_name, execution_id, _utcnow())
    return result


def validate_stage_context(scan_run_id: str, finding_id: str) -> None:
    """Reject a stage action whose scan-run context does not produce the finding.

    Raises :class:`StageContextError` (404 for an unknown run, 400 when the
    run's explicit lineage omits the finding — a cross-project or cross-run
    fabrication attempt). Membership is the persisted ``scan_findings``
    relationship; nothing is inferred from timestamps or paths.
    """
    store = get_scan_run_store()
    run = store.get_run(scan_run_id)
    if run is None:
        raise StageContextError(404, f"scan run not found: {scan_run_id}")
    if finding_id not in store.finding_ids_for_run(scan_run_id):
        raise StageContextError(
            400,
            f"scan run {scan_run_id} does not produce finding {finding_id}",
        )


def validate_stage_context_for_findings(
    scan_run_id: str, finding_ids: list[str]
) -> None:
    """List variant of :func:`validate_stage_context` (used by DEDUPLICATE):
    every submitted finding must be produced by the referenced run."""
    store = get_scan_run_store()
    run = store.get_run(scan_run_id)
    if run is None:
        raise StageContextError(404, f"scan run not found: {scan_run_id}")
    produced = set(store.finding_ids_for_run(scan_run_id))
    foreign = [fid for fid in finding_ids if fid not in produced]
    if foreign:
        raise StageContextError(
            400,
            f"scan run {scan_run_id} does not produce findings: {foreign}",
        )


class ScanRunService:
    """Orchestrates one synchronous scan execution and its lineage records."""

    def execute_scan(
        self,
        project_id: str,
        code_model: CodeModel,
        project_created_at=None,
    ) -> tuple[ScanRun, ScanReport]:
        """Run the SCAN stage and record run/stage/lineage state.

        ``project_created_at`` is the project's PREPARE completion time (the
        Project row's ``created_at``); it timestamps the recorded PREPARE
        execution. Returns ``(run, report)`` on success. On failure the
        failing stage and the run are marked ``failed`` with the error
        persisted, and the original exception is re-raised (never swallowed).
        """
        now = _utcnow()
        store = get_scan_run_store()
        scan_run_id = uuid4().hex
        run = ScanRun(
            scan_run_id=scan_run_id,
            project_id=project_id,
            status="running",
            started_at=now,
            created_at=now,
        )
        store.create_run(run)
        for name in STAGE_NAMES:
            store.upsert_stage(
                ScanStageRun(
                    scan_run_id=scan_run_id,
                    stage_name=name,
                    status="pending",
                )
            )

        # PREPARE: a scan run can only be created for an already-prepared
        # project, so the PREPARE stage genuinely completed before this run.
        # The real prepare time (project.created_at) timestamps the record
        # when the route provides it; otherwise the run start is used.
        prepare_at = (
            _ensure_aware_utc(project_created_at) if project_created_at else now
        )
        prepare_execution_id = uuid4().hex
        store.begin_stage_execution(
            scan_run_id, STAGE_PREPARE, prepare_execution_id, prepare_at
        )
        store.complete_stage_execution(
            scan_run_id, STAGE_PREPARE, prepare_execution_id, prepare_at
        )

        try:
            report = self._run_scan_stage(scan_run_id, project_id, code_model)
        except Exception as exc:  # noqa: BLE001 - failure boundary: persist, then re-raise
            logger.exception("SCAN run %s failed for project %s", scan_run_id, project_id)
            store.update_run(
                run.model_copy(
                    update={
                        "status": "failed",
                        "completed_at": _utcnow(),
                        "error": str(exc),
                    }
                )
            )
            raise

        completed = run.model_copy(
            update={
                "status": "completed",
                "completed_at": _utcnow(),
                "scanned_file_count": report.scanned_file_count,
                "total_findings": len(report.findings),
            }
        )
        store.update_run(completed)
        return completed, report

    @staticmethod
    def _run_scan_stage(
        scan_run_id: str, project_id: str, code_model: CodeModel
    ) -> ScanReport:
        """SCAN stage: existing ScanService + finding registration + lineage."""
        store = get_scan_run_store()

        def _do_scan() -> ScanReport:
            report = ScanService().scan(code_model, project_id=project_id)
            get_finding_store().add_report(report)
            for finding in report.findings:
                store.add_finding_lineage(scan_run_id, finding.id)
            return report

        return record_stage_execution(scan_run_id, STAGE_SCAN, _do_scan)