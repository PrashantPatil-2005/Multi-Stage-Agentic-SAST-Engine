"""Response models for the read-only validation summary endpoint.

GET /api/validation composes the existing validation, finding, risk and
proof stores into one snapshot for the Validation page. Nothing here
re-runs validation or recomputes verdicts; fields are null when the
corresponding store has no record.
"""

from datetime import datetime

from pydantic import BaseModel


class ValidationKpi(BaseModel):
    """One metric card value.

    ``available`` is False when the underlying store has never produced any
    data; the UI must then show "--" (not a fabricated number).
    """

    available: bool
    value: int


class ValidationKpis(BaseModel):
    total_validations: ValidationKpi
    true_positives: ValidationKpi
    false_positives: ValidationKpi
    uncertain: ValidationKpi
    # findings that have no validation record yet (only meaningful when
    # findings exist; same derivation as the dashboard "pending validation").
    pending: ValidationKpi


class ValidationRow(BaseModel):
    """One stored ValidationResult, enriched with finding/risk/proof context.

    ``evidence_used`` and ``reasoning`` come verbatim from the stored
    ValidationResult - they are never generated or rewritten here.
    """

    finding_id: str
    vulnerability_type: str | None
    severity: str | None
    priority: str | None  # from the stored risk assessment, when present
    repository: str | None
    file: str | None
    confidence: float | None  # validation confidence (0-1), never recalculated
    verdict: str | None  # true_positive / false_positive / uncertain
    reasoning: str | None
    evidence_used: list[str]
    validated_at: datetime | None
    proof_status: str | None  # from the proof store, when present


class ValidationSummary(BaseModel):
    has_findings: bool
    kpis: ValidationKpis
    records: list[ValidationRow]
