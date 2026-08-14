"""VALIDATE stage contracts.

A :class:`ValidationResult` records the LLM-assisted verdict for one
candidate finding. It never mutates the CandidateFinding itself - validation
information is stored separately.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.scan.models import TaintStep

Verdict = Literal["true_positive", "false_positive", "uncertain"]
NextStep = Literal["prove", "discard", "manual_review"]


class ValidationEvidence(BaseModel):
    """Deterministic, redacted evidence package sent to the LLM.

    Contains ONLY the code relevant to the finding - never the whole
    repository, and never raw secrets (redaction applied at build time).
    """

    finding_id: str
    vulnerability_type: str
    severity: str
    scanner_confidence: float
    source_file: str
    source_line: int
    source_snippet: str
    sink_file: str
    sink_line: int
    sink_snippet: str
    taint_path: list[TaintStep]
    relevant_lines: list[int]
    sanitizer_observations: list[str]
    surrounding_context: dict[str, list[str]] = Field(
        default_factory=dict, description="file -> nearby source lines (redacted)"
    )


class ValidationRequest(BaseModel):
    finding_id: str
    evidence: ValidationEvidence
    provider: str = "openai_compatible"
    model: str | None = None


class ValidationMetadata(BaseModel):
    provider: str
    model: str | None
    duration_ms: float
    retry_count: int
    evidence_hash: str


class ValidationResult(BaseModel):
    finding_id: str
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    evidence_used: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_next_step: NextStep
    model: str | None = None
    validated_at: datetime
    evidence: ValidationEvidence | None = None
    metadata: ValidationMetadata | None = None
