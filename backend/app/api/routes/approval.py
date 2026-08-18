"""Human approval workflow API endpoints.

POST /api/findings/{finding_id}/approval       - create an approval request
GET  /api/findings/{finding_id}/approval       - latest request for a finding
POST /api/approvals/{approval_id}/approve      - approve (terminal)
POST /api/approvals/{approval_id}/reject       - reject (terminal)
POST /api/approvals/{approval_id}/request-changes - return to review cycle
POST /api/approvals/{approval_id}/resubmit     - changes_requested -> pending
GET  /api/approvals                            - read-only review queue
GET  /api/approvals/{approval_id}/history      - audit event trail

Errors: 404 (missing finding/approval), 409 (gate failure or invalid
transition), 422 (invalid request body, incl. naive datetimes).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.api.approval_models import ApprovalListItem
from app.approval.models import ApprovalAction, ApprovalEvent, ApprovalRequest
from app.approval.service import (
    ApprovalGateError,
    ApprovalService,
    InvalidTransitionError,
)
from app.approval.store import get_approval_store
from app.core.time import as_aware_utc
from app.dedup.service import repo_label_for_file
from app.risk.service import all_risk_assessments
from app.scan.run_models import STAGE_APPROVAL
from app.scan.run_service import (
    StageContextError,
    record_stage_execution,
    validate_stage_context,
)
from app.validate.store import get_finding_store

router = APIRouter(tags=["approval"])

_STATUS_RANK = {
    "pending": 0,
    "changes_requested": 1,
    "approved": 2,
    "rejected": 3,
}


class ApprovalRequestIn(BaseModel):
    action: ApprovalAction = "remediation"
    requested_by: str = "system"
    scan_run_id: str | None = None


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


def _require_stage_context(scan_run_id: str, finding_id: str) -> None:
    try:
        validate_stage_context(scan_run_id, finding_id)
    except StageContextError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _transition(
    approval_id: str, body: ApprovalDecisionIn, method: str
) -> ApprovalRequest:
    request = _require_approval(approval_id)
    run_id = request.scan_run_id

    def _do_transition() -> ApprovalRequest:
        return getattr(ApprovalService(), method)(
            approval_id, reviewed_by=body.reviewed_by, reason=body.reason
        )

    if run_id is None:
        # Legacy / context-free request: no stage lineage, unchanged.
        try:
            return _do_transition()
        except InvalidTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    # Validate the transition BEFORE recording a stage execution so that
    # illegal transitions (e.g. reject after approve) do not pollute the
    # stage history with misleading "failed" records.
    from app.approval.service import ALLOWED_TRANSITIONS

    _METHOD_TARGET: dict[str, str] = {
        "approve": "approved",
        "reject": "rejected",
        "request_changes": "changes_requested",
        "resubmit": "pending",
    }
    target = _METHOD_TARGET.get(method, method)
    allowed = ALLOWED_TRANSITIONS.get(request.status, frozenset())
    if target not in allowed:
        raise HTTPException(
            status_code=409,
            detail=f"invalid approval transition: {request.status} -> {target} is not allowed",
        )
    try:
        return record_stage_execution(run_id, STAGE_APPROVAL, _do_transition)
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

    def _request() -> ApprovalRequest:
        return ApprovalService().request_approval(
            finding_id,
            action=payload.action,
            requested_by=payload.requested_by,
            scan_run_id=payload.scan_run_id,
        )

    if payload.scan_run_id is not None:
        _require_stage_context(payload.scan_run_id, finding_id)
        try:
            return record_stage_execution(
                payload.scan_run_id, STAGE_APPROVAL, _request
            )
        except ApprovalGateError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        return _request()
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
    "/approvals", response_model=list[ApprovalListItem]
)
def list_approvals() -> list[ApprovalListItem]:
    """Read-only review queue: every approval request with finding and
    risk context, pending first then newest request first. Never mutates
    approval state."""
    findings = {f.id: f for f in get_finding_store().all()}
    risks = {r.finding_id: r for r in all_risk_assessments()}
    items: list[ApprovalListItem] = []
    for request in get_approval_store().all():
        finding = findings.get(request.finding_id)
        assessment = risks.get(request.finding_id)
        items.append(
            ApprovalListItem(
                approval_id=request.id,
                finding_id=request.finding_id,
                status=request.status,
                action=request.action,
                version=request.version,
                requested_by=request.requested_by,
                requested_at=request.requested_at,
                reviewed_by=request.reviewed_by,
                reviewed_at=request.reviewed_at,
                reason=request.reason,
                vulnerability_type=(
                    finding.vulnerability_type if finding else None
                ),
                severity=finding.severity if finding else None,
                priority=assessment.priority if assessment else None,
                risk_score=assessment.risk_score if assessment else None,
                repository=(
                    repo_label_for_file(finding.source.file) if finding else None
                ),
                file=finding.source.file if finding else None,
            )
        )
    items.sort(
        key=lambda item: (
            _STATUS_RANK.get(item.status, 9),
            -as_aware_utc(item.requested_at).timestamp(),
        )
    )
    return items


@router.get(
    "/approvals/{approval_id}/history", response_model=list[ApprovalEvent]
)
def get_history(approval_id: str) -> list[ApprovalEvent]:
    _require_approval(approval_id)
    return ApprovalService().get_history(approval_id)