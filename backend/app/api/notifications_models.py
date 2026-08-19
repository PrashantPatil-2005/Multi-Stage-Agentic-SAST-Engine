"""Response models for the derived notifications endpoint.

Notifications are derived from existing persisted events (approval state
transitions, SLA escalations, validation completions, proof completions).
Each notification carries enough context for the frontend to render and
navigate to the relevant page.

Read/unread state is tracked per-user in a lightweight ``notifications``
table with ``read_at`` timestamp.
"""

from datetime import datetime

from pydantic import BaseModel


class Notification(BaseModel):
    id: str
    type: str  # "sla_breached" | "approval_updated" | "finding_validated" | "proof_completed"
    title: str
    message: str
    finding_id: str | None
    created_at: datetime
    read: bool


class NotificationList(BaseModel):
    notifications: list[Notification]
    unread_count: int
