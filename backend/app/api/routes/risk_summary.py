"""Read-only risk & SLA summary endpoint.

GET /api/risk/summary composes the existing in-memory stores into a single
snapshot for the Risk & SLA page. No risk/SLA business logic lives here and
nothing is ever mutated; the only computation is presentation-level
aggregation (counts, ordering, frozen remaining-time snapshots).
"""

from datetime import datetime, timezone

from fastapi import APIRouter

from app.api.risk_models import (
    EscalationRow,
    PriorityBucket,
    RiskBucket,
    RiskFindingRow,
    RiskKpi,
    RiskKpis,
    RiskSummary,
    SlaOverview,
    SlaRow,
)
from app.dedup.service import repo_label_for_file
from app.risk.models import SLARecord
from app.risk.service import (
    all_escalation_events,
    all_risk_assessments,
    all_sla_records,
)
from app.validate.store import get_finding_store, get_validation_store
from app.prove.store import get_proof_store

router = APIRouter(prefix="/risk", tags=["risk-summary"])

_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}

_RISK_BUCKETS = [
    ("0-20", 0, 20),
    ("21-40", 21, 40),
    ("41-60", 41, 60),
    ("61-80", 61, 80),
    ("81-100", 81, 100),
]


def _remaining_seconds(record: SLARecord, now: datetime) -> int | None:
    """Frozen snapshot of the time left for an active SLA (never negative)."""
    if record.status != "active" or record.due_at is None:
        return None
    return max(0, int((record.due_at - now).total_seconds()))


def _sla_row(record: SLARecord, now: datetime, findings: dict) -> SlaRow:
    finding = findings.get(record.finding_id)
    return SlaRow(
        finding_id=record.finding_id,
        vulnerability_type=finding.vulnerability_type if finding else None,
        priority=record.priority,
        started_at=record.started_at,
        due_at=record.due_at,
        status=record.status,
        escalation_level=record.escalation_level,
        breached_at=record.breached_at,
        remaining_seconds=_remaining_seconds(record, now),
    )


@router.get("/summary", response_model=RiskSummary)
def risk_summary() -> RiskSummary:
    findings = {f.id: f for f in get_finding_store().all()}
    validations = {v.finding_id: v for v in get_validation_store().all()}
    proofs = {p.finding_id: p for p in get_proof_store().all()}
    risks = all_risk_assessments()
    sla_records = all_sla_records()
    escalations = all_escalation_events()
    risk_by_finding = {r.finding_id: r for r in risks}
    now = datetime.now(timezone.utc)

    total = len(risks)

    priority_distribution: list[PriorityBucket] = []
    if total:
        for priority in ("P0", "P1", "P2", "P3", "P4"):
            count = sum(1 for r in risks if r.priority == priority)
            if count:
                priority_distribution.append(
                    PriorityBucket(
                        priority=priority,
                        count=count,
                        percent=round(count * 100 / total),
                    )
                )

    risk_distribution: list[RiskBucket] = []
    if total:
        for label, low, high in _RISK_BUCKETS:
            count = sum(1 for r in risks if low <= r.risk_score <= high)
            if count:
                risk_distribution.append(
                    RiskBucket(
                        label=label,
                        count=count,
                        percent=round(count * 100 / total),
                    )
                )

    ranked = sorted(
        risks,
        key=lambda r: (_PRIORITY_RANK.get(r.priority, 9), -r.risk_score),
    )
    highest_risk_findings: list[RiskFindingRow] = []
    for assessment in ranked:
        finding = findings.get(assessment.finding_id)
        if finding is None:
            continue
        sla = next(
            (s for s in sla_records if s.finding_id == finding.id), None
        )
        validation = validations.get(finding.id)
        proof = proofs.get(finding.id)
        highest_risk_findings.append(
            RiskFindingRow(
                finding_id=finding.id,
                priority=assessment.priority,
                risk_score=assessment.risk_score,
                severity=assessment.severity,
                vulnerability_type=finding.vulnerability_type,
                repository=repo_label_for_file(finding.source.file),
                file=finding.source.file,
                validation=validation.verdict if validation else None,
                proof=proof.status if proof else None,
                sla=sla.status if sla else "none",
                factors=assessment.factors,
            )
        )
        if len(highest_risk_findings) == 10:
            break

    active_rows = [
        _sla_row(record, now, findings)
        for record in sorted(
            [r for r in sla_records if r.status == "active"],
            key=lambda r: (
                _PRIORITY_RANK.get(r.priority, 9),
                _remaining_seconds(r, now) if r.due_at is not None else 0,
            ),
        )
    ]

    breach_rows = [
        _sla_row(record, now, findings)
        for record in sorted(
            [r for r in sla_records if r.status == "breached"],
            key=lambda r: (
                _PRIORITY_RANK.get(r.priority, 9),
                -(r.breached_at or datetime.min.replace(tzinfo=timezone.utc)).timestamp(),
            ),
        )
    ]

    escalation_rows = [
        EscalationRow(
            finding_id=event.finding_id,
            previous_level=event.previous_level,
            new_level=event.new_level,
            reason=event.reason,
            created_at=event.created_at,
            vulnerability_type=(
                findings[event.finding_id].vulnerability_type
                if event.finding_id in findings
                else None
            ),
            priority=(
                risk_by_finding[event.finding_id].priority
                if event.finding_id in risk_by_finding
                else None
            ),
        )
        for event in sorted(escalations, key=lambda e: e.created_at, reverse=True)
    ]

    return RiskSummary(
        has_findings=bool(findings),
        kpis=RiskKpis(
            total_assessments=RiskKpi(available=bool(risks), value=total),
            critical_p0=RiskKpi(
                available=bool(risks),
                value=sum(1 for r in risks if r.priority == "P0"),
            ),
            high_p1=RiskKpi(
                available=bool(risks),
                value=sum(1 for r in risks if r.priority == "P1"),
            ),
            active_slas=RiskKpi(
                available=bool(sla_records),
                value=sum(1 for r in sla_records if r.status == "active"),
            ),
            sla_breaches=RiskKpi(
                available=bool(sla_records),
                value=sum(1 for r in sla_records if r.status == "breached"),
            ),
            escalations=RiskKpi(
                available=bool(escalations), value=len(escalations)
            ),
        ),
        priority_distribution=priority_distribution,
        risk_distribution=risk_distribution,
        highest_risk_findings=highest_risk_findings,
        sla_overview=SlaOverview(
            available=bool(sla_records),
            active=sum(1 for r in sla_records if r.status == "active"),
            breached=sum(1 for r in sla_records if r.status == "breached"),
            resolved=sum(1 for r in sla_records if r.status == "resolved"),
            no_sla=sum(1 for r in sla_records if r.status == "not_applicable"),
        ),
        active_slas=active_rows,
        breaches=breach_rows,
        escalations=escalation_rows,
    )
