"""VALIDATE stage API endpoints.

POST /api/findings/{finding_id}/validate - run LLM validation on a candidate
GET  /api/findings/{finding_id}/validation - fetch the stored ValidationResult

``POST /api/findings/{id}/validate`` accepts an optional ``scan_run_id``
(Phase 14K): when present the run must exist AND its explicit lineage must
produce the finding (404/400 otherwise), and the VALIDATE stage of that run
is recorded as an explicit execution. Clients that omit ``scan_run_id`` are
unchanged - validation runs with no stage record.

Stage semantics: a successful validation API execution (any verdict) is
``completed``; an exception (including provider configuration failure,
which the route surfaces as 503) records ``failed`` with the real error.
Nothing here fabricates a verdict.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.scan.run_models import STAGE_VALIDATE
from app.scan.run_service import (
    StageContextError,
    record_stage_execution,
    validate_stage_context,
)
from app.validate.models import ValidationResult
from app.validate.providers.base import ConfigurationError
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["validation"])


class ValidateRequest(BaseModel):
    provider: str = "huggingface"
    scan_run_id: str | None = None


def get_validation_service() -> ValidationService:
    return ValidationService()


def _require_stage_context(scan_run_id: str, finding_id: str) -> None:
    try:
        validate_stage_context(scan_run_id, finding_id)
    except StageContextError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _validate_and_store(
    finding_id: str, provider: str, service: ValidationService
) -> ValidationResult:
    finding = get_finding_store().get(finding_id)
    result = service.validate(finding, provider_name=provider)
    get_validation_store().record(result)
    return result


@router.post("/{finding_id}/validate", response_model=ValidationResult)
def validate_finding(
    finding_id: str,
    body: ValidateRequest,
    service: ValidationService = Depends(get_validation_service),
) -> ValidationResult:
    if get_finding_store().get(finding_id) is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")

    if body.scan_run_id is not None:
        _require_stage_context(body.scan_run_id, finding_id)
        try:
            return record_stage_execution(
                body.scan_run_id,
                STAGE_VALIDATE,
                lambda: _validate_and_store(finding_id, body.provider, service),
            )
        except ConfigurationError as exc:
            logger.warning("VALIDATE unavailable for finding %s: %s", finding_id, exc)
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        result = service.validate(
            get_finding_store().get(finding_id), provider_name=body.provider
        )
    except ConfigurationError as exc:
        logger.warning("VALIDATE unavailable for finding %s: %s", finding_id, exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    get_validation_store().record(result)
    return result


@router.get("/{finding_id}/validation", response_model=ValidationResult)
def get_validation(finding_id: str) -> ValidationResult:
    result = get_validation_store().get(finding_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"no validation recorded for finding: {finding_id}",
        )
    return result
