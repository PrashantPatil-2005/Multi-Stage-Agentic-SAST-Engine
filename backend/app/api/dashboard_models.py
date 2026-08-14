"""Response models for the read-only dashboard summary endpoint.

The dashboard never exposes business logic of its own; it composes existing
stores into one read/summary payload for the frontend.
"""

from datetime import datetime

from pydantic import BaseModel


class DashboardProject(BaseModel):
    id: str
    name: str


class DashboardKpi(BaseModel):
    """One metric card value.

    ``available`` is False when the underlying store has never produced any
    data; the UI must then show "--" (not a fabricated number).
    """

    available: bool
    value: int


class DashboardPipelineStage(BaseModel):
    stage: str
    count: int | None
    count_label: str | None
    description: str


class DashboardFinding(BaseModel):
    finding_id: str
    priority: str | None
    vulnerability_type: str
    repository: str | None
    file: str
    status: str
    risk_score: int | None


class DashboardSlaSummary(BaseModel):
    available: bool
    active: int
    breached: int
    highest_priority_breach: str | None
    escalation_count: int


class DashboardVerification(BaseModel):
    available: bool
    true_positive: int
    false_positive: int
    uncertain: int
    verified: int
    not_verified: int
    blocked: int
    errors: int


class DashboardActivityItem(BaseModel):
    kind: str
    finding_id: str | None
    message: str
    created_at: datetime


class DashboardSummary(BaseModel):
    projects: list[DashboardProject]
    kpis: dict[str, DashboardKpi]
    pipeline: list[DashboardPipelineStage]
    critical_findings: list[DashboardFinding]
    sla: DashboardSlaSummary
    verification: DashboardVerification
    recent_activity: list[DashboardActivityItem]
