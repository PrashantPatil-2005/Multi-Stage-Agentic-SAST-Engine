"""PREPARE stage API endpoints.

POST   /api/projects           - ingest a repository (directory/zip/git) and build its snapshot
POST   /api/projects/{id}/scan - run the existing SCAN stage on a prepared project
GET    /api/projects/{id}      - retrieve project metadata + parsed file summary
DELETE /api/projects/{id}      - delete a repository and every pipeline record it owns
"""

import logging
import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.dashboard_models import DashboardProject
from app.api.schemas import FileMeta, ProjectDetail, ProjectOut, ScanResponse
from app.approval.store import get_approval_store
from app.auth.models import User
from app.auth.rbac import Permission, require_permission
from app.core.contracts import RepoSpec
from app.db.models import Project
from app.dedup.service import remove_findings
from app.prepare.fetcher import FetcherError, SecurityError
from app.prepare.service import PrepareError, PrepareService
from app.prove.store import get_proof_store
from app.remediation.store import get_remediation_store
from app.risk.service import remove_finding_state
from app.scan.run_service import ScanRunService
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["projects"])


def _prepare_service(request: Request) -> PrepareService:
    return request.app.state.prepare_service


def _remove_project_workspace(request: Request, project_id: str, snapshot_path: str) -> None:
    """Delete the prepared snapshot directory, guarded to the app workspace.

    Only ever removes the exact per-project directory the PREPARE stage
    created (``<workspace>/projects/<project_id>``); anything outside that
    layout is left untouched (a warning is logged).
    """
    settings = request.app.state.settings
    expected = (settings.workspace_dir / "projects" / project_id).resolve()
    actual = Path(snapshot_path).resolve()
    if actual != expected:
        logger.warning(
            "delete project %s: snapshot path %s is outside the workspace "
            "layout; leaving files on disk",
            project_id,
            snapshot_path,
        )
        return
    try:
        shutil.rmtree(actual)
    except OSError as exc:
        logger.warning(
            "delete project %s: could not remove workspace %s: %s",
            project_id,
            actual,
            exc,
        )


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(
    payload: RepoSpec,
    request: Request,
    user: User = Depends(require_permission(Permission.CREATE_REPOSITORY)),
) -> ProjectOut:
    project_id = uuid4().hex
    service = _prepare_service(request)
    try:
        snapshot, _, project_dir = service.prepare(payload, project_id)
    except SecurityError as exc:
        raise HTTPException(status_code=400, detail=f"security error: {exc}")
    except (FetcherError, PrepareError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - unexpected failure boundary
        logger.exception("PREPARE failed for project %s", project_id)
        raise HTTPException(status_code=500, detail="prepare failed")

    with request.app.state.session_factory() as session:
        session.add(
            Project(
                id=project_id,
                name=payload.name,
                source_type=payload.source_type,
                location=payload.location,
                language=payload.language,
                status="prepared",
                snapshot_path=str(project_dir),
                created_at=snapshot.created_at,
            )
        )
        session.commit()

    logger.info("project created: id=%s name=%s", project_id, payload.name)
    return ProjectOut(
        id=project_id,
        name=payload.name,
        source_type=payload.source_type,
        location=payload.location,
        language=payload.language,
        status="prepared",
        created_at=snapshot.created_at,
        summary=snapshot.summary,
    )


@router.post("/{project_id}/scan", response_model=ScanResponse)
def scan_project(
    project_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.SCAN)),
) -> ScanResponse:
    """Run the existing SCAN stage on a prepared project's stored CodeModel.

    Synchronous: the route finishes when the scan has run. A durable
    ScanRun (with stage + finding lineage) is recorded by the scan run
    orchestrator; the deterministic ScanService is reused unchanged and the
    resulting findings are registered in the finding store and become
    visible through the read-only /api/findings endpoints.
    """
    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
    try:
        code_model = PrepareService.load_code_model(Path(project.snapshot_path))
    except Exception as exc:  # noqa: BLE001 - unexpected failure boundary
        logger.exception("cannot load code model for project %s", project_id)
        raise HTTPException(status_code=500, detail="code model unavailable")

    run, report = ScanRunService().execute_scan(
        project_id, code_model, project_created_at=project.created_at
    )
    logger.info(
        "SCAN complete: project=%s run=%s findings=%d by_type=%s",
        project_id,
        run.scan_run_id,
        len(report.findings),
        report.summary.by_type,
    )
    return ScanResponse(
        report_id=report.id,
        scan_run_id=run.scan_run_id,
        project_id=project_id,
        created_at=report.created_at,
        scanned_file_count=report.scanned_file_count,
        total_findings=len(report.findings),
        by_type=report.summary.by_type,
        finding_ids=[f.id for f in report.findings],
    )


@router.get("", response_model=list[DashboardProject])
def list_projects(
    request: Request,
    user: User = Depends(require_permission(Permission.VIEW_REPOSITORIES)),
) -> list[DashboardProject]:
    """List ingested repositories (id + name), newest first."""
    with request.app.state.session_factory() as session:
        rows = session.query(Project).order_by(Project.created_at.desc()).all()
    return [DashboardProject(id=project.id, name=project.name) for project in rows]


@router.post("/{project_id}/reprepare", response_model=ProjectOut)
def reprepare_project(
    project_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.REPREPARE)),
) -> ProjectOut:
    """Re-run PREPARE against the existing workspace copy of the repository.

    Rebuilds ``snapshot.json`` and ``codemodel.json`` from the already-fetched
    ``workspace/projects/<id>/repo/`` directory (no re-fetch from git/zip, no
    network). This is what makes "apply a fix -> rescan" coherent: after a
    remediation patch the snapshot must reflect the patched code before a
    fresh scan can verify it.

    Errors: 404 (unknown project), 409 (workspace copy missing).
    """
    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
        snapshot_path = project.snapshot_path
        name = project.name
        source_type = project.source_type
        language = project.language
        location = project.location

    service = _prepare_service(request)
    try:
        snapshot, _, _ = service.reprepare(
            project_id=project_id,
            name=name,
            source_type=source_type,
            language=language,
            location=location,
            project_dir=Path(snapshot_path),
        )
    except PrepareError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - unexpected failure boundary
        logger.exception("REPREPARE failed for project %s", project_id)
        raise HTTPException(status_code=500, detail="reprepare failed")

    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
        project.status = "prepared"
        session.commit()

    logger.info("project reprepared: id=%s name=%s", project_id, name)
    return ProjectOut(
        id=project_id,
        name=name,
        source_type=source_type,
        location=location,
        language=language,
        status="prepared",
        created_at=snapshot.created_at,
        summary=snapshot.summary,
    )


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.DELETE_REPOSITORY)),
) -> None:
    """Delete a repository and every pipeline record it owns.

    Cascades over the persisted lineage (project -> scan runs -> findings)
    and removes the corresponding pipeline records: findings, validation,
    proof, risk/SLA/escalation, approval requests + audit events, dedup
    group membership and the prepared snapshot directory. Projects with no
    scans still get their row + workspace removed. Unknown projects 404.
    """
    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
        snapshot_path = project.snapshot_path

    run_store = get_scan_run_store()
    finding_ids: set[str] = set()
    for run in run_store.runs_for_project(project_id):
        finding_ids.update(run_store.finding_ids_for_run(run.scan_run_id))

    finding_store = get_finding_store()
    validation_store = get_validation_store()
    proof_store = get_proof_store()
    approval_store = get_approval_store()
    for finding_id in finding_ids:
        finding_store.remove(finding_id)
        validation_store.remove(finding_id)
        proof_store.remove(finding_id)
        remove_finding_state(finding_id)
        approval_store.remove_finding(finding_id)
        get_remediation_store().remove(finding_id)
    if finding_ids:
        remove_findings(finding_ids)
    run_store.delete_project_runs(project_id)

    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            # Row vanished between the two blocks (concurrent delete): the
            # pipeline records are already gone, so report a clean 404.
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
        session.delete(project)
        session.commit()

    _remove_project_workspace(request, project_id, snapshot_path)
    logger.info(
        "project deleted: id=%s findings_removed=%d",
        project_id,
        len(finding_ids),
    )


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(
    project_id: str,
    request: Request,
    user: User = Depends(require_permission(Permission.VIEW_REPOSITORIES)),
) -> ProjectDetail:
    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail=f"project not found: {project_id}")
        project_dir = Path(project.snapshot_path)
    try:
        snapshot = PrepareService.load_snapshot(project_dir)
    except (OSError, ValueError, KeyError) as exc:
        logger.exception("cannot load snapshot for project %s", project_id)
        raise HTTPException(status_code=500, detail="snapshot unavailable")

    files = [
        FileMeta(
            path=f.path,
            sha256=f.sha256,
            line_count=f.line_count,
            functions=len(f.functions),
            classes=len(f.classes),
            imports=len(f.imports),
            calls=len(f.calls),
            assignments=len(f.assignments),
            error=f.error,
        )
        for f in snapshot.files
    ]
    return ProjectDetail(
        id=project.id,
        name=project.name,
        source_type=project.source_type,
        location=project.location,
        language=project.language,
        status=project.status,
        created_at=project.created_at,
        summary=snapshot.summary,
        files=files,
    )
