"""PROVE stage contracts.

A :class:`ProofResult` records the outcome of a sandboxed, controlled
verification attempt for one validated finding. Proofs never attack real
systems: everything runs inside an isolated temporary workspace with a
strict :class:`SandboxPolicy`.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ProofStatus = Literal["verified", "not_verified", "blocked", "error"]


class ProofArtifact(BaseModel):
    """A small, controlled observation produced by the proof harness."""

    name: str
    kind: str  # e.g. "sql_statement", "marker", "url", "observation"
    content: str


class SandboxPolicy(BaseModel):
    """Explicit safety contract for one proof execution.

    Defaults are maximally restrictive; the proof engine never loosens
    ``network_enabled`` - only ``allow_loopback`` may be set (by the SSRF
    plan) for a harness-created, in-process, ephemeral loopback endpoint.
    """

    network_enabled: bool = False
    allow_loopback: bool = False
    allowed_paths: list[str] = Field(default_factory=list)
    timeout_seconds: float = 10.0
    max_output_bytes: int = 16 * 1024
    max_processes: int = 1
    temporary_directory: str = ""


class ProofRequest(BaseModel):
    """Internal request built by ProofService after the validation gate."""

    finding_id: str
    vulnerability_type: str
    objective: str
    input_value: str  # planner-controlled benign marker, never attacker payload
    harness: str  # approved harness name
    policy: SandboxPolicy


class ProofResult(BaseModel):
    finding_id: str
    vulnerability_type: str
    status: ProofStatus
    confidence: float = 0.0
    summary: str
    evidence: list[ProofArtifact] = Field(default_factory=list)
    artifacts: list[ProofArtifact] = Field(default_factory=list)
    duration_ms: float
    sandbox_policy: SandboxPolicy
    error: str | None = None
    created_at: datetime
