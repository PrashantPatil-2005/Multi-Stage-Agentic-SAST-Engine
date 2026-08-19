"""Read-only dashboard summary endpoint.

Composes the existing in-memory stores and the projects table into a single
summary payload for the frontend dashboard. No business logic lives here and
nothing is ever mutated.
"""

import logging

from fastapi import APIRouter, Depends, Query, Request

from app.auth.dependencies import get_current_user
from app.auth.models import User

from app.api.dashboard_models import (
    DashboardActivityItem,
    DashboardFinding,
    DashboardKpi,
    DashboardPipelineStage,
    DashboardProject,
    DashboardSlaSummary,
    DashboardSummary,
    DashboardVerification,
)
from app.approval.store import get_approval_store
from app.db.models import Project
from app.dedup.service import all_groups, repo_label_for_file
from app.core.time import as_aware_utc
from app.prove.store import get_proof_store
from app.remediation.store import get_remediation_store
from app.risk.service import (
    all_escalation_events,
    all_risk_assessments,
    all_sla_records,
)
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

_PIPELINE_DESCRIPTIONS: dict[str, str] = {
    "PREPARE": "Ingest repositories and build source snapshots",
    "SCAN": "Static analysis against bundled security rules",
    "DEDUP": "Group duplicate findings into unique issues",
    "RISK": "Risk scoring and SLA tracking per issue",
    "VALIDATE": "LLM triage of candidate findings",
    "PROVE": "Dynamic confirmation with sandboxed executions",
    "APPROVAL": "Human approval workflow",
    "REMEDIATION": "Auto-generated fix proposals and workspace patching",
}


def _finding_status(
    finding_id: str,
    validations: dict[str, object],
    proofs: dict[str, object],
    approvals: list[object],
) -> str:
    approval = next((a for a in approvals if a.finding_id == finding_id), None)
    if approval is not None:
        return {
            "approved": "approved",
            "rejected": "rejected",
            "changes_requested": "changes requested",
            "pending": "pending approval",
        }.get(approval.status, approval.status)
    proof = proofs.get(finding_id)
    if proof is not None:
        return proof.status.replace("_", " ")
    validation = validations.get(finding_id)
    if validation is not None:
        return validation.verdict.replace("_", " ")
    return "candidate"


def _activity(
    projects: list[object],
    validations: list[object],
    proofs: list[object],
    escalations: list[object],
    approval_events: list[object],
) -> list[DashboardActivityItem]:
    items: list[DashboardActivityItem] = []
    for project in projects:
        items.append(
            DashboardActivityItem(
                kind="project_created",
                finding_id=None,
                message=f"Repository '{project.name}' added",
                created_at=project.created_at,
            )
        )
    for validation in validations:
        items.append(
            DashboardActivityItem(
                kind="finding_validated",
                finding_id=validation.finding_id,
                message=(
                    f"Finding {validation.finding_id[:8]} triaged as "
                    f"{validation.verdict.replace('_', ' ')}"
                ),
                created_at=validation.validated_at,
            )
        )
    for proof in proofs:
        items.append(
            DashboardActivityItem(
                kind="proof_completed",
                finding_id=proof.finding_id,
                message=(
                    f"Proof {proof.status.replace('_', ' ')} for "
                    f"{proof.vulnerability_type}"
                ),
                created_at=proof.created_at,
            )
        )
    for event in escalations:
        items.append(
            DashboardActivityItem(
                kind="sla_breached",
                finding_id=event.finding_id,
                message=event.reason,
                created_at=event.created_at,
            )
        )
    for event in approval_events:
        items.append(
            DashboardActivityItem(
                kind="approval_updated",
                finding_id=event.finding_id,
                message=(
                    f"Approval moved to {event.new_status.replace('_', ' ')} "
                    f"({event.actor})"
                ),
                created_at=event.created_at,
            )
        )
    items.sort(key=lambda item: as_aware_utc(item.created_at), reverse=True)
    return items[:10]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _finding_ids_for_project(project_id: str) -> set[str] | None:
    """Resolve finding IDs that belong to *project_id* via scan run lineage.

    Returns ``None`` when the project has no scan runs (empty set is
    distinguishable from "no lineage").
    """
    run_store = get_scan_run_store()
    runs = run_store.runs_for_project(project_id)
    if not runs:
        return None  # project exists but has no scans
    ids: set[str] = set()
    for run in runs:
        ids.update(run_store.finding_ids_for_run(run.scan_run_id))
    return ids


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    request: Request,
    project_id: str | None = Query(default=None),
    user: User = Depends(get_current_user),
) -> DashboardSummary:
    finding_store = get_finding_store()

    # ── project-scoped filtering via scan run lineage ─────────────────
    scoped_finding_ids: set[str] | None = None
    scoped_project_rows: list[Project] | None = None  # None = no filter applied
    if project_id is not None and project_id != "all":
        with request.app.state.session_factory() as session:
            scoped_proj = session.get(Project, project_id)
        if scoped_proj is not None:
            scoped_project_rows = [scoped_proj]
        scoped_finding_ids = _finding_ids_for_project(project_id)
        if scoped_finding_ids is None:
            scoped_finding_ids = set()  # project with no scans → empty

    all_findings = finding_store.all()
    findings = {
        f.id: f
        for f in all_findings
        if scoped_finding_ids is None or f.id in scoped_finding_ids
    }

    all_validations = get_validation_store().all()
    validations = {
        v.finding_id: v
        for v in all_validations
        if scoped_finding_ids is None or v.finding_id in scoped_finding_ids
    }

    all_proofs = get_proof_store().all()
    proofs = {
        p.finding_id: p
        for p in all_proofs
        if scoped_finding_ids is None or p.finding_id in scoped_finding_ids
    }

    all_risks = all_risk_assessments()
    risks = [
        r
        for r in all_risks
        if scoped_finding_ids is None or r.finding_id in scoped_finding_ids
    ]

    all_sla = all_sla_records()
    sla_records = [
        r
        for r in all_sla
        if scoped_finding_ids is None or r.finding_id in scoped_finding_ids
    ]

    all_esc = all_escalation_events()
    escalations = [
        e
        for e in all_esc
        if scoped_finding_ids is None or e.finding_id in scoped_finding_ids
    ]

    all_approvals = get_approval_store().all()
    approvals = [
        a
        for a in all_approvals
        if scoped_finding_ids is None or a.finding_id in scoped_finding_ids
    ]

    all_approval_events = get_approval_store().all_events()
    approval_events = [
        e
        for e in all_approval_events
        if scoped_finding_ids is None or e.finding_id in scoped_finding_ids
    ]

    # Dedup and remediation are global — keep them unscoped for the
    # pipeline stage counts (they represent unique patterns, not
    # per-project counts).
    groups = all_groups()
    remediation_records = [
        r
        for r in get_remediation_store().all()
        if scoped_finding_ids is None or r.finding_id in scoped_finding_ids
    ]

    # Projects list: when scoped, show only the selected project;
    # otherwise show all.
    if scoped_project_rows is not None:
        project_rows = scoped_project_rows
    else:
        with request.app.state.session_factory() as session:
            project_rows = session.query(Project).order_by(Project.created_at.desc()).all()
    projects = [
        DashboardProject(id=project.id, name=project.name)
        for project in project_rows
    ]

    pending_approval_count = sum(
        1
        for a in approvals
        if a.status in ("pending", "changes_requested")
    )
    kpis = {
        "total_findings": DashboardKpi(
            available=bool(findings), value=len(findings)
        ),
        "critical_p0": DashboardKpi(
            available=bool(risks),
            value=sum(1 for r in risks if r.priority == "P0"),
        ),
        "sla_breaches": DashboardKpi(
            available=bool(sla_records),
            value=sum(1 for r in sla_records if r.status == "breached"),
        ),
        "pending_validation": DashboardKpi(
            available=bool(findings),
            value=max(0, len(findings) - len(validations)),
        ),
        "pending_approval": DashboardKpi(
            available=bool(findings),
            value=sum(
                1
                for a in approvals
                if a.status in ("pending", "changes_requested")
            ),
        ),
    }

    pipeline = [
        DashboardPipelineStage(
            stage="PREPARE",
            count=len(projects) if projects else None,
            count_label=_plural(len(projects), "repository", "repositories")
            if projects
            else None,
            description=_PIPELINE_DESCRIPTIONS["PREPARE"],
        ),
        DashboardPipelineStage(
            stage="SCAN",
            count=len(findings) if findings else None,
            count_label=_plural(len(findings), "finding", "findings")
            if findings
            else None,
            description=_PIPELINE_DESCRIPTIONS["SCAN"],
        ),
        DashboardPipelineStage(
            stage="DEDUP",
            count=len(groups) if groups else None,
            count_label=_plural(len(groups), "unique issue", "unique issues")
            if groups
            else None,
            description=_PIPELINE_DESCRIPTIONS["DEDUP"],
        ),
        DashboardPipelineStage(
            stage="RISK",
            count=len(risks) if risks else None,
            count_label=_plural(len(risks), "assessed issue", "assessed issues")
            if risks
            else None,
            description=_PIPELINE_DESCRIPTIONS["RISK"],
        ),
        DashboardPipelineStage(
            stage="VALIDATE",
            count=len(validations) if validations else None,
            count_label=_plural(len(validations), "validated", "validated")
            if validations
            else None,
            description=_PIPELINE_DESCRIPTIONS["VALIDATE"],
        ),
        DashboardPipelineStage(
            stage="PROVE",
            count=len(proofs) if proofs else None,
            count_label=_plural(len(proofs), "proof result", "proof results")
            if proofs
            else None,
            description=_PIPELINE_DESCRIPTIONS["PROVE"],
        ),
        DashboardPipelineStage(
            stage="APPROVAL",
            count=pending_approval_count if approvals else None,
            count_label=_plural(
                pending_approval_count, "pending approval", "pending approvals"
            )
            if approvals
            else None,
            description=_PIPELINE_DESCRIPTIONS["APPROVAL"],
        ),
        DashboardPipelineStage(
            stage="REMEDIATION",
            count=len(remediation_records) if remediation_records else None,
            count_label=_plural(
                len(remediation_records), "remediation", "remediations"
            )
            if remediation_records
            else None,
            description=_PIPELINE_DESCRIPTIONS["REMEDIATION"],
        ),
    ]

    ranked_risks = sorted(
        risks, key=lambda r: (_PRIORITY_RANK.get(r.priority, 9), -r.risk_score)
    )
    critical_findings: list[DashboardFinding] = []
    for assessment in ranked_risks:
        finding = findings.get(assessment.finding_id)
        if finding is None:
            continue
        critical_findings.append(
            DashboardFinding(
                finding_id=finding.id,
                priority=assessment.priority,
                vulnerability_type=finding.vulnerability_type,
                repository=repo_label_for_file(finding.source.file),
                file=finding.source.file,
                status=_finding_status(
                    finding.id, validations, proofs, approvals
                ),
                risk_score=assessment.risk_score,
            )
        )
        if len(critical_findings) == 5:
            break

    breached = [r for r in sla_records if r.status == "breached"]
    highest_breach = None
    if breached:
        highest_breach = min(breached, key=lambda r: _PRIORITY_RANK.get(r.priority, 9)).priority

    verification = DashboardVerification(
        available=bool(validations) or bool(proofs),
        true_positive=sum(1 for v in validations.values() if v.verdict == "true_positive"),
        false_positive=sum(1 for v in validations.values() if v.verdict == "false_positive"),
        uncertain=sum(1 for v in validations.values() if v.verdict == "uncertain"),
        verified=sum(1 for p in proofs.values() if p.status == "verified"),
        not_verified=sum(1 for p in proofs.values() if p.status == "not_verified"),
        blocked=sum(1 for p in proofs.values() if p.status == "blocked"),
        errors=sum(1 for p in proofs.values() if p.status == "error"),
    )

    return DashboardSummary(
        projects=projects,
        kpis=kpis,
        pipeline=pipeline,
        critical_findings=critical_findings,
        sla=DashboardSlaSummary(
            available=bool(sla_records),
            active=sum(1 for r in sla_records if r.status == "active"),
            breached=sum(1 for r in sla_records if r.status == "breached"),
            highest_priority_breach=highest_breach,
            escalation_count=len(escalations),
        ),
        verification=verification,
        recent_activity=_activity(
            project_rows,
            list(validations.values()),
            list(proofs.values()),
            escalations,
            approval_events,
        ),
    )
