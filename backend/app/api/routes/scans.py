"""Scan run lineage API endpoints (Phase 14D/14G).

GET /api/projects/{project_id}/scans   - scan history for a project
GET /api/scans                         - recent scan runs across projects
GET /api/scans/{scan_run_id}           - run detail incl. stage statuses
GET /api/scans/{scan_run_id}/findings  - findings produced by that run

All endpoints are read-only. Scans are synchronous: POST /api/projects/
{project_id}/scan finishes before it returns, and every run record is
already terminal (completed/failed) when it is served here.

Errors: 404 (unknown project or scan run).
"""

from fastapi import APIRouter, HTTPException, Query, Request

from app.db.models import Project
from app.scan.models import CandidateFinding
from app.scan.run_models import ScanRun, ScanRunDetail
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store

router = APIRouter(tags=["scans"])


def _require_project(project_id: str, request: Request) -> None:
    with request.app.state.session_factory() as session:
        if session.get(Project, project_id) is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )


def _require_run(scan_run_id: str) -> ScanRun:
    run = get_scan_run_store().get_run(scan_run_id)
    if run is None:
        raise HTTPException(
            status_code=404, detail=f"scan run not found: {scan_run_id}"
        )
    return run


@router.get("/scans", response_model=list[ScanRun])
def list_scan_runs(
    limit: int = Query(default=10, ge=1, le=50),
) -> list[ScanRun]:
    """Recent scan runs across all projects, newest first (read-only)."""
    runs = get_scan_run_store().all_runs()
    return sorted(runs, key=lambda r: r.started_at, reverse=True)[:limit]


@router.get("/projects/{project_id}/scans", response_model=list[ScanRun])
def list_project_scans(project_id: str, request: Request) -> list[ScanRun]:
    """Scan history for a project, newest first."""
    _require_project(project_id, request)
    return get_scan_run_store().runs_for_project(project_id)


@router.get("/scans/{scan_run_id}", response_model=ScanRunDetail)
def get_scan_run(scan_run_id: str) -> ScanRunDetail:
    """One scan run with the status of every registered stage and the
    append-only execution history of each stage."""
    store = get_scan_run_store()
    run = _require_run(scan_run_id)
    return ScanRunDetail(
        run=run,
        stages=store.stages_for_run(scan_run_id),
        executions=store.executions_for_run(scan_run_id),
    )


@router.get("/scans/{scan_run_id}/findings", response_model=list[CandidateFinding])
def get_scan_findings(scan_run_id: str) -> list[CandidateFinding]:
    """Findings produced by a scan run (explicit lineage, in report order).

    A finding registered by the run but no longer present in the finding
    store (e.g. after a test cleanup) is omitted; lineage is never inferred
    from timestamps or paths.
    """
    _require_run(scan_run_id)
    store = get_finding_store()
    findings = []
    for finding_id in get_scan_run_store().finding_ids_for_run(scan_run_id):
        finding = store.get(finding_id)
        if finding is not None:
            findings.append(finding)
    return findings