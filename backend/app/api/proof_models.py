"""Response models for the read-only proof summary endpoint.

GET /api/proof composes the existing proof, validation, finding and risk
stores into one snapshot for the Proof page. Nothing here executes a proof
or regenerates evidence; only the safe subset of each stored ProofResult is
exposed (no payloads, commands, paths or artifacts).
"""

from datetime import datetime

from pydantic import BaseModel


class ProofKpi(BaseModel):
    """One metric card value.

    ``available`` is False when the proof store has never produced any
    data; the UI must then show "--" (not a fabricated number).
    """

    available: bool
    value: int


class ProofKpis(BaseModel):
    total: ProofKpi
    verified: ProofKpi
    not_verified: ProofKpi
    blocked: ProofKpi
    errors: ProofKpi


class SandboxPolicyInfo(BaseModel):
    """Safe subset of the stored SandboxPolicy.

    Paths (``allowed_paths``, ``temporary_directory``) are deliberately
    excluded - they are sandbox/host filesystem details that must not be
    exposed to the UI.
    """

    network_enabled: bool
    allow_loopback: bool
    timeout_seconds: float
    max_output_bytes: int
    max_processes: int


class ProofRow(BaseModel):
    """One stored ProofResult, enriched with finding/risk/validation context.

    ``summary`` and ``error`` come verbatim from the stored ProofResult; no
    proof is ever re-run and no payloads or raw commands are included.
    """

    finding_id: str
    vulnerability_type: str | None
    severity: str | None
    priority: str | None  # from the stored risk assessment, when present
    validation: str | None  # stored verdict, when present
    status: str  # verified / not_verified / blocked / error
    confidence: float
    duration_ms: float
    created_at: datetime
    summary: str | None
    error: str | None
    repository: str | None
    file: str | None
    sandbox_policy: SandboxPolicyInfo | None


class ProofSummary(BaseModel):
    has_findings: bool
    kpis: ProofKpis
    records: list[ProofRow]
