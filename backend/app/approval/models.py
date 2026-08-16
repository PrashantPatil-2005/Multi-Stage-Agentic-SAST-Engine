"""Human approval workflow contracts.

An :class:`ApprovalRequest` is an explicit human-in-the-loop permission for
one finding + one action. :class:`ApprovalEvent` records every state
transition (append-only audit trail). Approval is a *permission state*
only: it never executes anything.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

ApprovalStatus = Literal["pending", "approved", "rejected", "changes_requested"]
ApprovalAction = Literal["remediation", "other"]


class ApprovalRequest(BaseModel):
    id: str
    finding_id: str
    status: ApprovalStatus
    requested_at: datetime
    requested_by: str
    reviewed_at: datetime | None = None
    reviewed_by: str | None = None
    reason: str | None = None
    action: ApprovalAction
    version: int
    #: Explicit scan-run context (Phase 14K): the run the approval workflow
    #: was requested against. Stored once at creation and inherited by every
    #: subsequent decision, so the reviewer never resends it. None for
    #: pre-14K requests or requests made without a run context.
    scan_run_id: str | None = None


class ApprovalEvent(BaseModel):
    id: str
    approval_id: str
    finding_id: str
    previous_status: ApprovalStatus | None
    new_status: ApprovalStatus
    actor: str
    reason: str | None = None
    created_at: datetime