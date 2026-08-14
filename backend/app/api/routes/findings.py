"""Read-only findings list endpoint.

GET /api/findings - enumerate candidate findings enriched with the available
risk, SLA, validation, proof and approval records from the in-memory stores.
Nothing is mutated; the endpoint is intentionally read-only.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Request

from app.api.findings_models import FindingListItem, FindingSlaInfo
from app.approval.store import get_approval_store
from app.dedup.service import repo_label_for_file
from app.prove.store import get_proof_store
from app.risk.service import (
    all_risk_assessments,
    all_sla_records,
)
from app.validate.store import get_finding_store, get_validation_store

router = APIRouter(prefix="/findings", tags=["findings"])


def _sla_info(finding_id: str, now: datetime) -> FindingSlaInfo:
    record = all_sla_records()
    sla = next((r for r in record if r.finding_id == finding_id), None)
    if sla is None:
        return FindingSlaInfo(
            status="none", remaining_seconds=None, priority=None
        )
    remaining_seconds = None
    if sla.status == "active" and sla.due_at is not None:
        remaining_seconds = max(0, int((sla.due_at - now).total_seconds()))
    return FindingSlaInfo(
        status=sla.status,
        remaining_seconds=remaining_seconds,
        priority=sla.priority,
    )


@router.get("", response_model=list[FindingListItem])
def list_findings(request: Request) -> list[FindingListItem]:
    findings = get_finding_store().all()
    if not findings:
        return []

    validations = {v.finding_id: v for v in get_validation_store().all()}
    proofs = {p.finding_id: p for p in get_proof_store().all()}
    risks = {r.finding_id: r for r in all_risk_assessments()}
    approval_store = get_approval_store()
    now = datetime.now(timezone.utc)

    items: list[FindingListItem] = []
    for finding in sorted(findings, key=lambda f: f.id):
        assessment = risks.get(finding.id)
        validation = validations.get(finding.id)
        proof = proofs.get(finding.id)
        approval = approval_store.find_for_finding(finding.id)
        items.append(
            FindingListItem(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                severity=finding.severity,
                scanner_confidence=finding.confidence,
                priority=assessment.priority if assessment else None,
                risk_score=assessment.risk_score if assessment else None,
                repository=repo_label_for_file(finding.source.file),
                file=finding.source.file,
                source_snippet=finding.source.snippet,
                sink_snippet=finding.sink.snippet,
                source_kind=finding.source.kind,
                sink_kind=finding.sink.kind,
                verdict=validation.verdict if validation else None,
                validation_confidence=(
                    validation.confidence if validation else None
                ),
                validated_at=validation.validated_at if validation else None,
                proof_status=proof.status if proof else None,
                approval_status=approval.status if approval else None,
                sla=_sla_info(finding.id, now),
            )
        )
    return items
