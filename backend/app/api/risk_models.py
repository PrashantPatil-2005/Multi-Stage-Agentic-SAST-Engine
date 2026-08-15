"""Response models for the read-only risk & SLA summary endpoint.

The summary composes the existing risk, SLA, escalation, validation, proof
and finding stores into one snapshot for the Risk & SLA page. Nothing here
computes new risk values or SLA policy; fields are null when the
corresponding store has no record.
"""

from datetime import datetime

from pydantic import BaseModel

from app.risk.models import RiskFactor


class RiskKpi(BaseModel):
    """One metric card value.

    ``available`` is False when the underlying store has never produced any
    data; the UI must then show "--" (not a fabricated number).
    """

    available: bool
    value: int


class RiskKpis(BaseModel):
    total_assessments: RiskKpi
    critical_p0: RiskKpi
    high_p1: RiskKpi
    active_slas: RiskKpi
    sla_breaches: RiskKpi
    escalations: RiskKpi


class PriorityBucket(BaseModel):
    """One priority level present in the store (count + share)."""

    priority: str  # "P0" .. "P4"
    count: int
    percent: int


class RiskBucket(BaseModel):
    """One risk-score range present in the store (count + share)."""

    label: str  # e.g. "61-80"
    count: int
    percent: int


class RiskFindingRow(BaseModel):
    """One ranked finding for the highest-risk table."""

    finding_id: str
    priority: str
    risk_score: int
    severity: str
    vulnerability_type: str
    repository: str | None
    file: str
    validation: str | None  # verdict, or null when not validated
    proof: str | None  # proof status, or null when not proven
    sla: str  # record status, or "none" when no record exists
    factors: list[RiskFactor]


class SlaOverview(BaseModel):
    available: bool
    active: int
    breached: int
    resolved: int
    no_sla: int  # records whose priority has no deadline (not_applicable)


class SlaRow(BaseModel):
    """One SLA record snapshot (remaining time frozen at request time)."""

    finding_id: str
    vulnerability_type: str | None
    priority: str
    started_at: datetime
    due_at: datetime | None
    status: str
    escalation_level: int
    breached_at: datetime | None
    remaining_seconds: int | None


class EscalationRow(BaseModel):
    """One escalation event, enriched with finding/assessment context."""

    finding_id: str
    previous_level: int
    new_level: int
    reason: str
    created_at: datetime
    vulnerability_type: str | None
    priority: str | None


class RiskSummary(BaseModel):
    has_findings: bool
    kpis: RiskKpis
    priority_distribution: list[PriorityBucket]
    risk_distribution: list[RiskBucket]
    highest_risk_findings: list[RiskFindingRow]
    sla_overview: SlaOverview
    active_slas: list[SlaRow]
    breaches: list[SlaRow]
    escalations: list[EscalationRow]
