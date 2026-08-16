"""PREPARE stage API endpoints.

POST /api/projects           - ingest a repository (directory/zip/git) and build its snapshot
POST /api/projects/{id}/scan - run the existing SCAN stage on a prepared project
GET  /api/projects/{id}      - retrieve project metadata + parsed file summary
"""

import logging
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from app.api.dashboard_models import DashboardProject
from app.api.schemas import FileMeta, ProjectDetail, ProjectOut, ScanResponse
from app.core.contracts import RepoSpec
from app.db.models import Project
from app.prepare.fetcher import FetcherError, SecurityError
from app.prepare.service import PrepareError, PrepareService
from app.scan.service import ScanService
from app.validate.store import get_finding_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/projects", tags=["projects"])


def _prepare_service(request: Request) -> PrepareService:
    return request.app.state.prepare_service


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(payload: RepoSpec, request: Request) -> ProjectOut:
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
def scan_project(project_id: str, request: Request) -> ScanResponse:
    """Run the existing SCAN stage on a prepared project's stored CodeModel.

    Reuses the deterministic ScanService unchanged; the resulting findings
    are registered in the in-memory finding store and become visible through
    the read-only /api/findings endpoints.
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

    report = ScanService().scan(code_model)
    get_finding_store().add_report(report)
    logger.info(
        "SCAN complete: project=%s findings=%d by_type=%s",
        project_id,
        len(report.findings),
        report.summary.by_type,
    )
    return ScanResponse(
        report_id=report.id,
        project_id=project_id,
        created_at=report.created_at,
        scanned_file_count=report.scanned_file_count,
        total_findings=len(report.findings),
        by_type=report.summary.by_type,
        finding_ids=[f.id for f in report.findings],
    )


@router.get("", response_model=list[DashboardProject])
def list_projects(request: Request) -> list[DashboardProject]:
    """List ingested repositories (id + name), newest first."""
    with request.app.state.session_factory() as session:
        rows = session.query(Project).order_by(Project.created_at.desc()).all()
    return [DashboardProject(id=project.id, name=project.name) for project in rows]


@router.get("/{project_id}", response_model=ProjectDetail)
def get_project(project_id: str, request: Request) -> ProjectDetail:
    with request.app.state.session_factory() as session:
        project = session.get(Project, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail=f"project not found: {project_id}")
        project_dir = Path(project.snapshot_path)
    try:
        snapshot = PrepareService.load_snapshot(project_dir)
    except OSError as exc:
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
