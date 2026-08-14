"""Response models for the read-only findings list endpoint.

One entry composes the candidate finding with whatever risk, SLA, validation,
proof and approval records exist for it. Nothing here computes business
values; fields are null when the corresponding store has no record.
"""

from datetime import datetime

from pydantic import BaseModel


class FindingSlaInfo(BaseModel):
    status: str  # "active" | "breached" | "resolved" | "not_applicable" | "none"
    remaining_seconds: int | None
    priority: str | None


class FindingListItem(BaseModel):
    finding_id: str
    vulnerability_type: str
    severity: str
    scanner_confidence: float
    priority: str | None
    risk_score: int | None
    repository: str | None
    file: str
    source_snippet: str
    sink_snippet: str
    source_kind: str
    sink_kind: str
    verdict: str | None
    validation_confidence: float | None
    validated_at: datetime | None
    proof_status: str | None
    approval_status: str | None
    sla: FindingSlaInfo
