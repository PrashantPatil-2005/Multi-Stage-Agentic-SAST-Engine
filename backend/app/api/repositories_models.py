"""Response models for the read-only repositories summary endpoint.

The endpoint composes the projects table with read-only aggregates over the
existing finding/risk/validation/proof/SLA stores. Nothing is mutated and no
business logic lives here: every value below mirrors stored records.
"""

from datetime import datetime

from pydantic import BaseModel


class RepositoryFindings(BaseModel):
    """Finding totals for one repository (attributed via its snapshot files)."""

    total: int
    by_priority: dict[str, int]  # P0..P4, zero-filled; priority comes from RiskAssessment
    highest_priority: str | None


class RepositoryRisk(BaseModel):
    """Highest risk recorded for the repository's findings."""

    available: bool
    highest_risk_score: int | None
    highest_priority: str | None
    top_finding_id: str | None  # real finding id of the highest-priority finding


class RepositoryValidation(BaseModel):
    """Validation verdict counts for the repository's findings."""

    available: bool
    true_positive: int
    false_positive: int
    uncertain: int


class RepositoryProof(BaseModel):
    """Proof status counts for the repository's findings."""

    available: bool
    verified: int
    not_verified: int
    blocked: int
    error: int


class RepositorySla(BaseModel):
    """SLA status counts for the repository's findings."""

    available: bool
    active: int
    breached: int
    resolved: int


class RepositorySummary(BaseModel):
    """One registered project with its derived finding summaries.

    ``findings``/``risk``/``validation``/``proof``/``sla`` are ``None`` when
    the data cannot be reliably associated with the project; the frontend
    renders dashes in that case and never fabricates values.
    """

    project_id: str
    name: str
    source_type: str
    language: str
    status: str
    location: str
    created_at: datetime
    findings: RepositoryFindings | None
    risk: RepositoryRisk | None
    validation: RepositoryValidation | None
    proof: RepositoryProof | None
    sla: RepositorySla | None


class RepositoryList(BaseModel):
    has_repositories: bool
    repositories: list[RepositorySummary]
