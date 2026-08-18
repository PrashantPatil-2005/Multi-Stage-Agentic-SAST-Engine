"""Read-only proof summary endpoint.

GET /api/proof composes the existing in-memory stores into a single
snapshot for the Proof page. No proof business logic lives here and nothing
is ever mutated; the only computation is presentation-level aggregation
(counts, ordering, field joins). Only the safe ProofResult subset is
exposed - no payloads, commands, paths or artifacts.
"""

from fastapi import APIRouter

from app.api.proof_models import (
    ProofKpi,
    ProofKpis,
    ProofRow,
    ProofSummary,
    SandboxPolicyInfo,
)
from app.core.time import as_aware_utc
from app.dedup.service import repo_label_for_file
from app.prove.store import get_proof_store
from app.risk.service import all_risk_assessments
from app.validate.store import get_finding_store, get_validation_store

router = APIRouter(prefix="/proof", tags=["proof-summary"])


def _safe_policy(policy) -> SandboxPolicyInfo | None:
    if policy is None:
        return None
    return SandboxPolicyInfo(
        network_enabled=policy.network_enabled,
        allow_loopback=policy.allow_loopback,
        timeout_seconds=policy.timeout_seconds,
        max_output_bytes=policy.max_output_bytes,
        max_processes=policy.max_processes,
    )


@router.get("", response_model=ProofSummary)
def proof_summary() -> ProofSummary:
    findings = {f.id: f for f in get_finding_store().all()}
    proofs = get_proof_store().all()
    validations = {v.finding_id: v for v in get_validation_store().all()}
    risks = {r.finding_id: r for r in all_risk_assessments()}

    records: list[ProofRow] = []
    for result in sorted(
        proofs, key=lambda p: as_aware_utc(p.created_at), reverse=True
    ):
        finding = findings.get(result.finding_id)
        assessment = risks.get(result.finding_id)
        validation = validations.get(result.finding_id)
        records.append(
            ProofRow(
                finding_id=result.finding_id,
                vulnerability_type=result.vulnerability_type,
                severity=finding.severity if finding else None,
                priority=assessment.priority if assessment else None,
                validation=validation.verdict if validation else None,
                status=result.status,
                confidence=result.confidence,
                duration_ms=result.duration_ms,
                created_at=result.created_at,
                summary=result.summary,
                error=result.error,
                repository=(
                    repo_label_for_file(finding.source.file) if finding else None
                ),
                file=finding.source.file if finding else None,
                sandbox_policy=_safe_policy(result.sandbox_policy),
            )
        )

    return ProofSummary(
        has_findings=bool(findings),
        kpis=ProofKpis(
            total=ProofKpi(available=bool(proofs), value=len(proofs)),
            verified=ProofKpi(
                available=bool(proofs),
                value=sum(1 for p in proofs if p.status == "verified"),
            ),
            not_verified=ProofKpi(
                available=bool(proofs),
                value=sum(1 for p in proofs if p.status == "not_verified"),
            ),
            blocked=ProofKpi(
                available=bool(proofs),
                value=sum(1 for p in proofs if p.status == "blocked"),
            ),
            errors=ProofKpi(
                available=bool(proofs),
                value=sum(1 for p in proofs if p.status == "error"),
            ),
        ),
        records=records,
    )
