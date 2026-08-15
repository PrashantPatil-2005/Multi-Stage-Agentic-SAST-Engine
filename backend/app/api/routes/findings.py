"""Read-only findings endpoints.

GET /api/findings            - enumerate candidate findings enriched with the
                               available risk, SLA, validation, proof and
                               approval records from the in-memory stores.
GET /api/findings/{id}       - the complete read-only story of one finding,
                               composing the same stores plus dedup membership.
Nothing is mutated; both endpoints are intentionally read-only.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.api.findings_models import (
    FindingDetail,
    FindingDedupDetail,
    FindingListItem,
    FindingProofDetail,
    FindingSlaDetail,
    FindingSlaInfo,
)
from app.approval.store import get_approval_store
from app.dedup.service import all_groups, repo_label_for_file
from app.prove.store import get_proof_store
from app.risk.service import (
    all_risk_assessments,
    all_sla_records,
    get_risk_assessment,
    get_sla_record,
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


def _sla_detail(finding_id: str, now: datetime) -> FindingSlaDetail | None:
    record = get_sla_record(finding_id)
    if record is None:
        return None
    remaining_seconds = None
    if record.status == "active" and record.due_at is not None:
        remaining_seconds = max(0, int((record.due_at - now).total_seconds()))
    return FindingSlaDetail(
        status=record.status,
        priority=record.priority,
        started_at=record.started_at,
        due_at=record.due_at,
        breached_at=record.breached_at,
        resolved_at=record.resolved_at,
        escalation_level=record.escalation_level,
        remaining_seconds=remaining_seconds,
    )


def _proof_detail(finding_id: str) -> FindingProofDetail | None:
    proof = get_proof_store().get(finding_id)
    if proof is None:
        return None
    policy = proof.sandbox_policy.model_dump() if proof.sandbox_policy else None
    return FindingProofDetail(
        status=proof.status,
        confidence=proof.confidence,
        summary=proof.summary,
        created_at=proof.created_at,
        duration_ms=proof.duration_ms,
        error=proof.error,
        sandbox_policy=policy,
    )


def _dedup_detail(finding_id: str) -> FindingDedupDetail | None:
    group = next(
        (g for g in all_groups() if finding_id in g.member_finding_ids), None
    )
    if group is None:
        return None
    return FindingDedupDetail(
        fingerprint=group.fingerprint,
        structural_signature=group.structural_signature,
        is_canonical=group.canonical_finding_id == finding_id,
        canonical_finding_id=group.canonical_finding_id,
        occurrence_count=group.occurrence_count,
        related_finding_ids=[
            member
            for member in group.member_finding_ids
            if member != finding_id
        ],
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding_detail(finding_id: str) -> FindingDetail:
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")

    assessment = get_risk_assessment(finding_id)
    validation = get_validation_store().get(finding_id)
    approval = get_approval_store().find_for_finding(finding_id)
    now = datetime.now(timezone.utc)

    return FindingDetail(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        scanner_confidence=finding.confidence,
        status=finding.status,
        repository=repo_label_for_file(finding.source.file),
        source=finding.source,
        sink=finding.sink,
        taint_path=finding.taint_path,
        risk=assessment,
        sla=_sla_detail(finding_id, now),
        validation=validation,
        proof=_proof_detail(finding_id),
        approval=approval,
        dedup=_dedup_detail(finding_id),
    )
