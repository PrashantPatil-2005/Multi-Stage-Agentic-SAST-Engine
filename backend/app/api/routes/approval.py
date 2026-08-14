"""Human approval workflow API endpoints.

POST /api/findings/{finding_id}/approval       - create an approval request
GET  /api/findings/{finding_id}/approval       - latest request for a finding
POST /api/approvals/{approval_id}/approve      - approve (terminal)
POST /api/approvals/{approval_id}/reject       - reject (terminal)
POST /api/approvals/{approval_id}/request-changes - return to review cycle
GET  /api/approvals/{approval_id}/history      - audit event trail

Errors: 404 (missing finding/approval), 409 (gate failure or invalid
transition), 422 (invalid request body, incl. naive datetimes).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.approval.models import ApprovalAction, ApprovalEvent, ApprovalRequest
from app.approval.service import (
    ApprovalGateError,
    ApprovalService,
    InvalidTransitionError,
)
from app.approval.store import get_approval_store
from app.validate.store import get_finding_store

router = APIRouter(tags=["approval"])


class ApprovalRequestIn(BaseModel):
    action: ApprovalAction = "remediation"
    requested_by: str = "system"


class ApprovalDecisionIn(BaseModel):
    reviewed_by: str
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def _not_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("reason must not be blank")
        return value


def _require_finding(finding_id: str):
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
    return finding


def _require_approval(approval_id: str) -> ApprovalRequest:
    request = get_approval_store().get(approval_id)
    if request is None:
        raise HTTPException(
            status_code=404, detail=f"approval not found: {approval_id}"
        )
    return request


def _transition(
    approval_id: str, body: ApprovalDecisionIn, method: str
) -> ApprovalRequest:
    _require_approval(approval_id)
    try:
        return getattr(ApprovalService(), method)(
            approval_id, reviewed_by=body.reviewed_by, reason=body.reason
        )
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/findings/{finding_id}/approval", response_model=ApprovalRequest
)
def request_approval(
    finding_id: str, body: ApprovalRequestIn | None = None
) -> ApprovalRequest:
    _require_finding(finding_id)
    payload = body or ApprovalRequestIn()
    try:
        return ApprovalService().request_approval(
            finding_id,
            action=payload.action,
            requested_by=payload.requested_by,
        )
    except ApprovalGateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/findings/{finding_id}/approval", response_model=ApprovalRequest
)
def get_approval(finding_id: str) -> ApprovalRequest:
    request = get_approval_store().find_for_finding(finding_id)
    if request is None:
        raise HTTPException(
            status_code=404, detail=f"no approval request for finding: {finding_id}"
        )
    return request


@router.post(
    "/approvals/{approval_id}/approve", response_model=ApprovalRequest
)
def approve(approval_id: str, body: ApprovalDecisionIn) -> ApprovalRequest:
    return _transition(approval_id, body, "approve")


@router.post(
    "/approvals/{approval_id}/reject", response_model=ApprovalRequest
)
def reject(approval_id: str, body: ApprovalDecisionIn) -> ApprovalRequest:
    return _transition(approval_id, body, "reject")


@router.post(
    "/approvals/{approval_id}/request-changes",
    response_model=ApprovalRequest,
)
def request_changes(
    approval_id: str, body: ApprovalDecisionIn
) -> ApprovalRequest:
    return _transition(approval_id, body, "request_changes")


@router.post(
    "/approvals/{approval_id}/resubmit", response_model=ApprovalRequest
)
def resubmit(approval_id: str, body: ApprovalDecisionIn) -> ApprovalRequest:
    """changes_requested -> pending (new review cycle, version + 1)."""
    return _transition(approval_id, body, "resubmit")


@router.get(
    "/approvals/{approval_id}/history", response_model=list[ApprovalEvent]
)
def get_history(approval_id: str) -> list[ApprovalEvent]:
    _require_approval(approval_id)
    return ApprovalService().get_history(approval_id)