"""Risk prioritization + SLA tracking contracts.

A :class:`RiskAssessment` turns one (canonical) finding into a transparent,
deterministic risk score and priority. An :class:`SLARecord` tracks the
fix deadline derived from that priority, and :class:`EscalationEvent`
records level transitions (SLA breach -> level 1).

All timestamps are timezone-aware UTC; naive datetimes are rejected.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

Priority = Literal["P0", "P1", "P2", "P3", "P4"]
SlaStatus = Literal["not_applicable", "active", "breached", "resolved"]


class RiskFactor(BaseModel):
    """One explainable contributor to a risk score."""

    name: str
    value: str
    points: int
    description: str


class RiskAssessment(BaseModel):
    finding_id: str
    vulnerability_type: str
    severity: str
    risk_score: int  # 0-100, deterministic
    priority: Priority
    factors: list[RiskFactor]
    assessed_at: datetime
    related_finding_ids: list[str] = []  # dedup group members (traceability)


class SLARecord(BaseModel):
    finding_id: str
    priority: Priority
    started_at: datetime
    due_at: datetime | None  # None when the priority has no SLA (P4)
    status: SlaStatus
    breached_at: datetime | None = None
    escalation_level: int = 0
    last_checked_at: datetime | None = None
    resolved_at: datetime | None = None


class EscalationEvent(BaseModel):
    finding_id: str
    previous_level: int
    new_level: int
    reason: str
    created_at: datetime