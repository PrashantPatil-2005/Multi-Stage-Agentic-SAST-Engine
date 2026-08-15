"""Response models for the read-only approval review queue.

The review queue composes the approval store with the finding and risk
stores. It is deliberately read-only: approval business logic lives in
``app/approval/service.py`` and is never duplicated here.
"""

from datetime import datetime

from pydantic import BaseModel


class ApprovalListItem(BaseModel):
    """One row of the review queue (approval + finding + risk context)."""

    approval_id: str
    finding_id: str
    status: str
    action: str
    version: int
    requested_by: str
    requested_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    reason: str | None
    vulnerability_type: str | None
    severity: str | None
    priority: str | None
    risk_score: int | None
    repository: str | None
    file: str | None
