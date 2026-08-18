"""PROVE stage API endpoints.

POST /api/findings/{finding_id}/prove - run a sandboxed proof for a validated finding
GET  /api/findings/{finding_id}/proof - fetch the stored ProofResult

``POST /api/findings/{id}/prove`` accepts an optional body
``{"scan_run_id": ...}`` (Phase 14K): when present the run must exist AND
its explicit lineage must produce the finding (404/400 otherwise), and the
PROVE stage of that run is recorded as an explicit execution. Clients that
omit the body are unchanged - the proof runs with no stage record.

Stage semantics (from ProofResult): ``verified`` / ``not_verified`` /
``blocked`` mean the proof execution itself completed (``completed``);
a returned ``ProofResult(status="error")`` - sandbox timeout, harness
failure, execution exception - is a failed execution (``failed`` with the
real error). A gate rejection (409, verdict not true_positive) is also
recorded as ``failed`` because the explicit PROVE action failed before
running. The sandbox service itself is never modified here.

Errors:
* 404 - finding or validation result missing
* 409 - finding is not eligible for proof (verdict is not true_positive)
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.prove.models import ProofResult
from app.prove.service import ProofGateError, ProofService
from app.prove.store import get_proof_store
from app.scan.run_models import STAGE_PROVE
from app.scan.run_service import (
    StageContextError,
    record_stage_execution,
    validate_stage_context,
)
from app.validate.store import get_finding_store, get_validation_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["proof"])


class ProveRequest(BaseModel):
    scan_run_id: str | None = None


class SafeProofDetail(BaseModel):
    """Safe read-only proof summary for GET /findings/{id}/proof.

    Deliberately excludes ``evidence``/``artifacts`` (raw harness output,
    generated payloads) and the host-path fields of ``sandbox_policy``
    (``allowed_paths``, ``temporary_directory``): execution details and
    sandbox internals are never shipped to clients.
    """

    finding_id: str
    vulnerability_type: str
    status: str  # "verified" | "not_verified" | "blocked" | "error"
    confidence: float
    summary: str
    created_at: datetime
    duration_ms: float
    error: str | None
    sandbox_policy: dict | None


def _safe_policy(proof: ProofResult) -> dict | None:
    if proof.sandbox_policy is None:
        return None
    data = proof.sandbox_policy.model_dump()
    data.pop("allowed_paths", None)
    data.pop("temporary_directory", None)
    return data


def get_proof_service() -> ProofService:
    return ProofService()


def _require_stage_context(scan_run_id: str, finding_id: str) -> None:
    try:
        validate_stage_context(scan_run_id, finding_id)
    except StageContextError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


def _prove_and_store(
    finding_id: str, service: ProofService
) -> ProofResult:
    finding = get_finding_store().get(finding_id)
    validation = get_validation_store().get(finding_id)
    result = service.prove(finding, validation)
    get_proof_store().record(result)
    return result


def _proof_error_condition(result: ProofResult):
    if result.status == "error":
        return True, result.error or "proof execution returned status=error"
    return False, ""


@router.post("/{finding_id}/prove", response_model=ProofResult)
def prove_finding(
    finding_id: str,
    body: ProveRequest | None = None,
    service: ProofService = Depends(get_proof_service),
) -> ProofResult:
    if get_finding_store().get(finding_id) is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")

    # When a scan-run context is supplied, lineage is validated before the
    # gates: a foreign/unknown run is rejected before any proof eligibility
    # check runs (explicit run/finding lineage first, then existing gates).
    if body is not None and body.scan_run_id is not None:
        _require_stage_context(body.scan_run_id, finding_id)
        if get_validation_store().get(finding_id) is None:
            raise HTTPException(
                status_code=404, detail=f"validation result missing: {finding_id}"
            )
        try:
            return record_stage_execution(
                body.scan_run_id,
                STAGE_PROVE,
                lambda: _prove_and_store(finding_id, service),
                error_condition=_proof_error_condition,
            )
        except ProofGateError as exc:
            logger.info("PROVE gate rejected finding %s: %s", finding_id, exc)
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    if get_validation_store().get(finding_id) is None:
        raise HTTPException(
            status_code=404, detail=f"validation result missing: {finding_id}"
        )
    try:
        result = service.prove(
            get_finding_store().get(finding_id),
            get_validation_store().get(finding_id),
        )
    except ProofGateError as exc:
        logger.info("PROVE gate rejected finding %s: %s", finding_id, exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    get_proof_store().record(result)
    return result


@router.get("/{finding_id}/proof", response_model=SafeProofDetail)
def get_proof(finding_id: str) -> SafeProofDetail:
    result = get_proof_store().get(finding_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"no proof recorded for finding: {finding_id}",
        )
    return SafeProofDetail(
        finding_id=result.finding_id,
        vulnerability_type=result.vulnerability_type,
        status=result.status,
        confidence=result.confidence,
        summary=result.summary,
        created_at=result.created_at,
        duration_ms=result.duration_ms,
        error=result.error,
        sandbox_policy=_safe_policy(result),
    )