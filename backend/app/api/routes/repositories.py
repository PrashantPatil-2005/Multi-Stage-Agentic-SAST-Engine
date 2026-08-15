"""Read-only repositories summary endpoint.

GET /api/repositories - registered projects with read-only aggregates over
the existing in-memory finding/risk/validation/proof/SLA stores.

Association convention: findings do not carry a repository id, so a finding
is attributed to a project when the finding's source file is a file of that
project's snapshot (the finding's file came from the project's fetched repo).
This is the path-based convention the rest of the application uses
(see ``repo_label_for_file`` in app/dedup/service.py); no new relation is
introduced and nothing is ever mutated.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Request

from app.api.repositories_models import (
    RepositoryFindings,
    RepositoryList,
    RepositoryProof,
    RepositoryRisk,
    RepositorySla,
    RepositorySummary,
    RepositoryValidation,
)
from app.db.models import Project
from app.prepare.service import PrepareService
from app.prove.store import get_proof_store
from app.risk.service import all_risk_assessments, all_sla_records
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/repositories", tags=["repositories"])

_PRIORITIES = ["P0", "P1", "P2", "P3", "P4"]
_PRIORITY_RANK = {p: i for i, p in enumerate(_PRIORITIES)}

_VERDICTS = ("true_positive", "false_positive", "uncertain")
_PROOF_STATUSES = ("verified", "not_verified", "blocked", "error")
_SLA_STATUSES = ("active", "breached", "resolved")


def _project_files(project: Project) -> set[str] | None:
    """Files of the project snapshot, or None when the snapshot is unavailable."""
    try:
        snapshot = PrepareService.load_snapshot(Path(project.snapshot_path))
    except (OSError, ValueError) as exc:
        logger.warning(
            "repositories: cannot load snapshot for project %s: %s",
            project.id,
            exc,
        )
        return None
    return {f.path for f in snapshot.files}


def _summarize(project: Project, files: set[str] | None) -> RepositorySummary:
    finding_store = get_finding_store()
    if files is None or not finding_store.all():
        return RepositorySummary(
            project_id=project.id,
            name=project.name,
            source_type=project.source_type,
            language=project.language,
            status=project.status,
            location=project.location,
            created_at=project.created_at,
            findings=None,
            risk=None,
            validation=None,
            proof=None,
            sla=None,
        )

    findings = {f.id: f for f in finding_store.all() if f.source.file in files}
    if not findings:
        return RepositorySummary(
            project_id=project.id,
            name=project.name,
            source_type=project.source_type,
            language=project.language,
            status=project.status,
            location=project.location,
            created_at=project.created_at,
            findings=None,
            risk=None,
            validation=None,
            proof=None,
            sla=None,
        )

    assessments = {
        r.finding_id: r
        for r in all_risk_assessments()
        if r.finding_id in findings
    }
    validations = {
        v.finding_id: v
        for v in get_validation_store().all()
        if v.finding_id in findings
    }
    proofs = {
        p.finding_id: p for p in get_proof_store().all() if p.finding_id in findings
    }
    sla_records = {
        s.finding_id: s for s in all_sla_records() if s.finding_id in findings
    }

    by_priority = {p: 0 for p in _PRIORITIES}
    for assessment in assessments.values():
        by_priority[assessment.priority] += 1
    ranked = sorted(
        assessments.values(),
        key=lambda a: (_PRIORITY_RANK.get(a.priority, 9), -a.risk_score),
    )
    top = ranked[0] if ranked else None

    return RepositorySummary(
        project_id=project.id,
        name=project.name,
        source_type=project.source_type,
        language=project.language,
        status=project.status,
        location=project.location,
        created_at=project.created_at,
        findings=RepositoryFindings(
            total=len(findings),
            by_priority=by_priority,
            highest_priority=top.priority if top else None,
        ),
        risk=(
            RepositoryRisk(
                available=True,
                highest_risk_score=top.risk_score if top else None,
                highest_priority=top.priority if top else None,
                top_finding_id=top.finding_id if top else None,
            )
            if assessments
            else None
        ),
        validation=(
            RepositoryValidation(
                available=True,
                true_positive=sum(
                    1 for v in validations.values() if v.verdict == "true_positive"
                ),
                false_positive=sum(
                    1 for v in validations.values() if v.verdict == "false_positive"
                ),
                uncertain=sum(
                    1 for v in validations.values() if v.verdict == "uncertain"
                ),
            )
            if validations
            else None
        ),
        proof=(
            RepositoryProof(
                available=True,
                verified=sum(1 for p in proofs.values() if p.status == "verified"),
                not_verified=sum(
                    1 for p in proofs.values() if p.status == "not_verified"
                ),
                blocked=sum(1 for p in proofs.values() if p.status == "blocked"),
                error=sum(1 for p in proofs.values() if p.status == "error"),
            )
            if proofs
            else None
        ),
        sla=(
            RepositorySla(
                available=True,
                active=sum(1 for s in sla_records.values() if s.status == "active"),
                breached=sum(1 for s in sla_records.values() if s.status == "breached"),
                resolved=sum(1 for s in sla_records.values() if s.status == "resolved"),
            )
            if sla_records
            else None
        ),
    )


@router.get("", response_model=RepositoryList)
def list_repositories(request: Request) -> RepositoryList:
    with request.app.state.session_factory() as session:
        projects = (
            session.query(Project).order_by(Project.created_at.desc()).all()
        )
    if not projects:
        return RepositoryList(has_repositories=False, repositories=[])
    return RepositoryList(
        has_repositories=True,
        repositories=[_summarize(p, _project_files(p)) for p in projects],
    )
