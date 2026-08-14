"""PROVE stage API endpoints.

POST /api/findings/{finding_id}/prove - run a sandboxed proof for a validated finding
GET  /api/findings/{finding_id}/proof - fetch the stored ProofResult

Errors:
* 404 - finding or validation result missing
* 409 - finding is not eligible for proof (verdict is not true_positive)
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.prove.models import ProofResult
from app.prove.service import ProofGateError, ProofService
from app.prove.store import get_proof_store
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["proof"])


def get_proof_service() -> ProofService:
    return ProofService()


@router.post("/{finding_id}/prove", response_model=ProofResult)
def prove_finding(
    finding_id: str,
    service: ProofService = Depends(get_proof_service),
) -> ProofResult:
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
    validation = get_validation_store().get(finding_id)
    if validation is None:
        raise HTTPException(
            status_code=404, detail=f"validation result missing: {finding_id}"
        )
    try:
        result = service.prove(finding, validation)
    except ProofGateError as exc:
        logger.info("PROVE gate rejected finding %s: %s", finding_id, exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    get_proof_store().record(result)
    return result


@router.get("/{finding_id}/proof", response_model=ProofResult)
def get_proof(finding_id: str) -> ProofResult:
    result = get_proof_store().get(finding_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"no proof recorded for finding: {finding_id}",
        )
    return result