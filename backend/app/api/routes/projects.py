"""PREPARE stage API endpoints.

POST /api/projects   - ingest a repository (directory/zip/git) and build its snapshot
GET  /api/projects/{id} - retrieve project metadata + parsed file summary
"""

import logging
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from app.api.dashboard_models import DashboardProject
from app.api.schemas import FileMeta, ProjectDetail, ProjectOut
from app.core.contracts import RepoSpec
from app.db.models import Project
from app.prepare.fetcher import FetcherError, SecurityError
from app.prepare.service import PrepareError, PrepareService

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
        raise HTTPException(status_code=500, detail=f"prepare failed: {exc}")

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
        raise HTTPException(status_code=500, detail=f"snapshot unavailable: {exc}")

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
