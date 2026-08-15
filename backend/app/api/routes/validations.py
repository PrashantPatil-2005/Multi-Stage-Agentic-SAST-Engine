"""VALIDATE stage API endpoints.

POST /api/findings/{finding_id}/validate - run LLM validation on a candidate
GET  /api/findings/{finding_id}/validation - fetch the stored ValidationResult

Findings are looked up in the in-memory FindingStore (see validate/store.py);
validation results are recorded separately from the findings themselves.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.validate.models import ValidationResult
from app.validate.providers.base import ConfigurationError
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["validation"])


class ValidateRequest(BaseModel):
    provider: str = "huggingface"


def get_validation_service() -> ValidationService:
    return ValidationService()


@router.post("/{finding_id}/validate", response_model=ValidationResult)
def validate_finding(
    finding_id: str,
    body: ValidateRequest,
    service: ValidationService = Depends(get_validation_service),
) -> ValidationResult:
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
    try:
        result = service.validate(finding, provider_name=body.provider)
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
