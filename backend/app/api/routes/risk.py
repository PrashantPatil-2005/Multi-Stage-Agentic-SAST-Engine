"""Risk prioritization + SLA + escalation API endpoints.

POST /api/findings/{finding_id}/risk          - assess (uses stored validation/proof)
GET  /api/findings/{finding_id}/risk          - stored RiskAssessment
POST /api/findings/{finding_id}/sla           - create SLARecord from stored risk
GET  /api/findings/{finding_id}/sla           - stored SLARecord
POST /api/findings/{finding_id}/sla/check     - evaluate deadline (optional test time)
POST /api/findings/{finding_id}/sla/resolve   - mark resolved (optional test time)
GET  /api/findings/{finding_id}/escalations   - escalation event history

Errors: 404 (missing finding / risk / sla), 422 (naive datetime supplied).
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.auth.models import User
from app.auth.rbac import Permission, require_permission
from app.prove.store import get_proof_store
from app.risk.models import (
    EscalationEvent,
    RiskAssessment,
    SLARecord,
)
from app.risk.service import (
    RiskService,
    SLAService,
    check_and_persist_sla,
    get_escalation_events,
    get_risk_assessment,
    get_sla_record,
    record_risk_assessment,
    record_sla_record,
)
from app.scan.run_models import STAGE_RISK, STAGE_SLA
from app.scan.run_service import (
    StageContextError,
    record_stage_execution,
    validate_stage_context,
)
from app.validate.store import get_finding_store, get_validation_store

router = APIRouter(prefix="/findings", tags=["risk"])


def _require_finding(finding_id: str):
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
    return finding


def _require_risk(finding_id: str) -> RiskAssessment:
    assessment = get_risk_assessment(finding_id)
    if assessment is None:
        raise HTTPException(
            status_code=404, detail=f"no risk assessment for finding: {finding_id}"
        )
    return assessment


def _require_sla(finding_id: str) -> SLARecord:
    record = get_sla_record(finding_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"no SLA record for finding: {finding_id}"
        )
    return record


def _parse_time(value: datetime | None, what: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(
            status_code=422,
            detail=f"{what} must be a timezone-aware ISO-8601 datetime (e.g. 2026-01-01T00:00:00Z)",
        )
    return value


class RiskStageRequest(BaseModel):
    """Optional scan-run context for one per-finding stage action.

    When present the action is recorded as an explicit execution of the
    RISK/SLA stage against that run (Phase 14J). Clients that omit it are
    unchanged: the action still runs, with no stage record.
    """

    scan_run_id: str | None = None


class SlaCheckRequest(BaseModel):
    now: datetime | None = None
    scan_run_id: str | None = None

    @field_validator("now")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return value


class SlaResolveRequest(BaseModel):
    resolved_at: datetime | None = None

    @field_validator("resolved_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("resolved_at must be timezone-aware")
        return value


class SlaCheckResult(BaseModel):
    sla: SLARecord
    escalation: EscalationEvent | None


def _assess_risk(finding_id: str) -> RiskAssessment:
    finding = _require_finding(finding_id)
    validation = get_validation_store().get(finding_id)
    proof = get_proof_store().get(finding_id)
    assessment = RiskService().assess(finding, validation, proof)
    record_risk_assessment(assessment)
    return assessment


def _require_stage_context(scan_run_id: str, finding_id: str) -> None:
    try:
        validate_stage_context(scan_run_id, finding_id)
    except StageContextError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


@router.post("/{finding_id}/risk", response_model=RiskAssessment)
def assess_risk(
    finding_id: str,
    body: RiskStageRequest | None = None,
    user: User = Depends(require_permission(Permission.ASSESS_RISK)),
) -> RiskAssessment:
    if body is not None and body.scan_run_id is not None:
        _require_stage_context(body.scan_run_id, finding_id)
        return record_stage_execution(
            body.scan_run_id, STAGE_RISK, lambda: _assess_risk(finding_id)
        )
    return _assess_risk(finding_id)


@router.get("/{finding_id}/risk", response_model=RiskAssessment)
def get_risk(
    finding_id: str,
    user: User = Depends(require_permission(Permission.VIEW_RISK)),
) -> RiskAssessment:
    return _require_risk(finding_id)


def _start_sla(finding_id: str) -> SLARecord:
    assessment = _require_risk(finding_id)
    existing = get_sla_record(finding_id)
    if existing is not None and existing.priority == assessment.priority:
        return existing
    record = SLAService().create_sla(assessment)
    record_sla_record(record)
    return record


@router.post("/{finding_id}/sla", response_model=SLARecord)
def create_sla(
    finding_id: str,
    body: RiskStageRequest | None = None,
    user: User = Depends(require_permission(Permission.START_SLA)),
) -> SLARecord:
    if body is not None and body.scan_run_id is not None:
        _require_stage_context(body.scan_run_id, finding_id)
        return record_stage_execution(
            body.scan_run_id, STAGE_SLA, lambda: _start_sla(finding_id)
        )
    return _start_sla(finding_id)


@router.get("/{finding_id}/sla", response_model=SLARecord)
def get_sla(
    finding_id: str,
    user: User = Depends(require_permission(Permission.VIEW_RISK)),
) -> SLARecord:
    return _require_sla(finding_id)


def _check_sla(finding_id: str, body: SlaCheckRequest | None) -> SlaCheckResult:
    now = _parse_time(body.now if body else None, "now")
    updated, event = check_and_persist_sla(finding_id, now)
    if updated is None:
        raise HTTPException(
            status_code=404, detail=f"no SLA record for finding: {finding_id}"
        )
    return SlaCheckResult(sla=updated, escalation=event)


@router.post("/{finding_id}/sla/check", response_model=SlaCheckResult)
def check_sla(
    finding_id: str,
    body: SlaCheckRequest | None = None,
    user: User = Depends(require_permission(Permission.CHECK_SLA)),
) -> SlaCheckResult:
    if body is not None and body.scan_run_id is not None:
        _require_stage_context(body.scan_run_id, finding_id)
        return record_stage_execution(
            body.scan_run_id, STAGE_SLA, lambda: _check_sla(finding_id, body)
        )
    return _check_sla(finding_id, body)


@router.post("/{finding_id}/sla/resolve", response_model=SLARecord)
def resolve_sla(
    finding_id: str,
    body: SlaResolveRequest | None = None,
    user: User = Depends(require_permission(Permission.CHECK_SLA)),
) -> SLARecord:
    record = _require_sla(finding_id)
    resolved_at = _parse_time(body.resolved_at if body else None, "resolved_at")
    updated = SLAService().resolve_sla(record, resolved_at)
    record_sla_record(updated)
    return updated


@router.get("/{finding_id}/escalations", response_model=list[EscalationEvent])
def get_escalations(
    finding_id: str,
    user: User = Depends(require_permission(Permission.VIEW_RISK)),
) -> list[EscalationEvent]:
    _require_finding(finding_id)
    return get_escalation_events(finding_id)