"""Response models for the read-only findings endpoints.

The list entry composes the candidate finding with whatever risk, SLA,
validation, proof and approval records exist for it. The detail view
(GET /api/findings/{finding_id}) composes the full read-only story of one
finding from the existing stores. Nothing here computes business values;
fields are null when the corresponding store has no record.
"""

from datetime import datetime

from pydantic import BaseModel

from app.approval.models import ApprovalRequest
from app.remediation.models import RemediationRecord
from app.risk.models import RiskAssessment
from app.scan.models import SinkRef, SourceRef, TaintStep
from app.scan.run_models import ScanRun
from app.validate.models import ValidationResult


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


class FindingSlaDetail(BaseModel):
    """SLA snapshot for the detail view (remaining time frozen at request
    time - the frontend must not compute a live countdown)."""

    status: str  # "active" | "breached" | "resolved" | "not_applicable"
    priority: str | None
    started_at: datetime | None
    due_at: datetime | None
    breached_at: datetime | None
    resolved_at: datetime | None
    escalation_level: int
    remaining_seconds: int | None


class FindingProofDetail(BaseModel):
    """Safe read-only proof summary.

    Deliberately excludes ``evidence``/``artifacts``: execution details and
    observations are internal proof-harness output and are never shipped to
    the frontend. Only the backend-provided safe summary is exposed.
    """

    status: str  # "verified" | "not_verified" | "blocked" | "error"
    confidence: float
    summary: str
    created_at: datetime
    duration_ms: float
    error: str | None
    sandbox_policy: dict | None


class FindingProject(BaseModel):
    """Authoritative project/repository that owns a finding.

    Derived exclusively from the explicit scan lineage (project -> scan run
    -> finding); never from file paths or repository labels.
    """

    project_id: str
    name: str
    source_type: str
    location: str
    language: str


class FindingDedupDetail(BaseModel):
    """Deduplication membership for one finding (group view)."""

    fingerprint: str
    structural_signature: str
    is_canonical: bool
    canonical_finding_id: str
    occurrence_count: int
    related_finding_ids: list[str]


class FindingDetail(BaseModel):
    """Complete read-only story of one finding.

    The candidate finding is included verbatim (source, sink, taint path),
    enriched with whatever risk, SLA, validation, proof, approval and
    deduplication records exist. Nothing is computed here beyond what the
    stores already hold.
    """

    finding_id: str
    vulnerability_type: str
    severity: str
    scanner_confidence: float
    status: str
    repository: str | None
    source: SourceRef
    sink: SinkRef
    taint_path: list[TaintStep]
    risk: RiskAssessment | None
    sla: FindingSlaDetail | None
    validation: ValidationResult | None
    proof: FindingProofDetail | None
    approval: ApprovalRequest | None
    dedup: FindingDedupDetail | None
    #: Post-approval remediation workflow record (proposal/diff + apply/verify
    #: state), when one exists.
    remediation: RemediationRecord | None = None
    #: Authoritative lineage (Phase 14G): owning project plus every scan run
    #: whose explicit scan_findings lineage produced this finding (newest
    #: first). Both are derived from persisted relationships only.
    project: FindingProject | None = None
    scan_runs: list[ScanRun] = []
