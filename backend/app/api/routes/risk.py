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

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.prove.store import get_proof_store
from app.risk.models import (
    EscalationEvent,
    RiskAssessment,
    SLARecord,
)
from app.risk.service import (
    RiskService,
    SLAService,
    get_escalation_events,
    get_risk_assessment,
    get_sla_record,
    record_escalation_event,
    record_risk_assessment,
    record_sla_record,
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


class SlaCheckRequest(BaseModel):
    now: datetime | None = None

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


@router.post("/{finding_id}/risk", response_model=RiskAssessment)
def assess_risk(finding_id: str) -> RiskAssessment:
    finding = _require_finding(finding_id)
    validation = get_validation_store().get(finding_id)
    proof = get_proof_store().get(finding_id)
    assessment = RiskService().assess(finding, validation, proof)
    record_risk_assessment(assessment)
    return assessment


@router.get("/{finding_id}/risk", response_model=RiskAssessment)
def get_risk(finding_id: str) -> RiskAssessment:
    return _require_risk(finding_id)


@router.post("/{finding_id}/sla", response_model=SLARecord)
def create_sla(finding_id: str) -> SLARecord:
    assessment = _require_risk(finding_id)
    existing = get_sla_record(finding_id)
    if existing is not None and existing.priority == assessment.priority:
        return existing
    record = SLAService().create_sla(assessment)
    record_sla_record(record)
    return record


@router.get("/{finding_id}/sla", response_model=SLARecord)
def get_sla(finding_id: str) -> SLARecord:
    return _require_sla(finding_id)


@router.post("/{finding_id}/sla/check", response_model=SlaCheckResult)
def check_sla(finding_id: str, body: SlaCheckRequest | None = None) -> SlaCheckResult:
    record = _require_sla(finding_id)
    now = _parse_time(body.now if body else None, "now")
    updated, event = SLAService().check_sla(record, now)
    record_sla_record(updated)
    if event is not None:
        record_escalation_event(event)
    return SlaCheckResult(sla=updated, escalation=event)


@router.post("/{finding_id}/sla/resolve", response_model=SLARecord)
def resolve_sla(
    finding_id: str, body: SlaResolveRequest | None = None
) -> SLARecord:
    record = _require_sla(finding_id)
    resolved_at = _parse_time(body.resolved_at if body else None, "resolved_at")
    updated = SLAService().resolve_sla(record, resolved_at)
    record_sla_record(updated)
    return updated


@router.get("/{finding_id}/escalations", response_model=list[EscalationEvent])
def get_escalations(finding_id: str) -> list[EscalationEvent]:
    _require_finding(finding_id)
    return get_escalation_events(finding_id)