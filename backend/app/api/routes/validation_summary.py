"""Read-only validation summary endpoint.

GET /api/validation composes the existing in-memory stores into a single
snapshot for the Validation page. No validation business logic lives here
and nothing is ever mutated; the only computation is presentation-level
aggregation (counts, ordering, field joins).
"""

from fastapi import APIRouter, Depends

from app.auth.dependencies import get_current_user
from app.auth.models import User

from app.api.validation_models import (
    ValidationKpi,
    ValidationKpis,
    ValidationRow,
    ValidationSummary,
)
from app.core.time import as_aware_utc
from app.dedup.service import repo_label_for_file
from app.prove.store import get_proof_store
from app.risk.service import all_risk_assessments
from app.validate.store import get_finding_store, get_validation_store

router = APIRouter(prefix="/validation", tags=["validation-summary"])


@router.get("", response_model=ValidationSummary)
def validation_summary(user: User = Depends(get_current_user)) -> ValidationSummary:
    findings = {f.id: f for f in get_finding_store().all()}
    validations = get_validation_store().all()
    proofs = {p.finding_id: p for p in get_proof_store().all()}
    risks = {r.finding_id: r for r in all_risk_assessments()}

    records: list[ValidationRow] = []
    for result in sorted(
        validations, key=lambda v: as_aware_utc(v.validated_at), reverse=True
    ):
        finding = findings.get(result.finding_id)
        assessment = risks.get(result.finding_id)
        records.append(
            ValidationRow(
                finding_id=result.finding_id,
                vulnerability_type=(
                    finding.vulnerability_type if finding else None
                ),
                severity=finding.severity if finding else None,
                priority=assessment.priority if assessment else None,
                repository=(
                    repo_label_for_file(finding.source.file) if finding else None
                ),
                file=finding.source.file if finding else None,
                confidence=result.confidence,
                verdict=result.verdict,
                reasoning=result.reasoning,
                evidence_used=list(result.evidence_used),
                validated_at=result.validated_at,
                proof_status=(
                    proofs[result.finding_id].status
                    if result.finding_id in proofs
                    else None
                ),
            )
        )

    return ValidationSummary(
        has_findings=bool(findings),
        kpis=ValidationKpis(
            total_validations=ValidationKpi(
                available=bool(validations), value=len(validations)
            ),
            true_positives=ValidationKpi(
                available=bool(validations),
                value=sum(1 for v in validations if v.verdict == "true_positive"),
            ),
            false_positives=ValidationKpi(
                available=bool(validations),
                value=sum(1 for v in validations if v.verdict == "false_positive"),
            ),
            uncertain=ValidationKpi(
                available=bool(validations),
                value=sum(1 for v in validations if v.verdict == "uncertain"),
            ),
            pending=ValidationKpi(
                available=bool(findings),
                value=max(0, len(findings) - len(validations)),
            ),
        ),
        records=records,
    )
