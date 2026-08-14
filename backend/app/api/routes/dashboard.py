"""Read-only dashboard summary endpoint.

Composes the existing in-memory stores and the projects table into a single
summary payload for the frontend dashboard. No business logic lives here and
nothing is ever mutated.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Request

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
from app.prove.store import get_proof_store
from app.risk.service import (
    all_escalation_events,
    all_risk_assessments,
    all_sla_records,
)
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
}


def _finding_status(
    finding_id: str,
    validations: dict[str, object],
    proofs: dict[str, object],
    approvals: list[object],
) -> str:
    approval = next((a for a in approvals if a.finding_id == finding_id), None)
    if approval is not None:
        return "approved" if approval.status == "approved" else "pending approval"
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
    items.sort(key=lambda item: item.created_at, reverse=True)
    return items[:10]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(request: Request) -> DashboardSummary:
    finding_store = get_finding_store()
    findings = {f.id: f for f in finding_store.all()}
    validations = {v.finding_id: v for v in get_validation_store().all()}
    proofs = {p.finding_id: p for p in get_proof_store().all()}
    risks = all_risk_assessments()
    sla_records = all_sla_records()
    escalations = all_escalation_events()
    approvals = get_approval_store().all()
    approval_events = get_approval_store().all_events()
    groups = all_groups()

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
            available=bool(approvals), value=pending_approval_count
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
