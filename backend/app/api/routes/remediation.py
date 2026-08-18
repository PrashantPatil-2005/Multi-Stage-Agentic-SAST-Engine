"""Remediation API endpoints (post-approval, human-confirmed fixes).

GET  /api/findings/{id}/remediation            - stored RemediationRecord
POST /api/findings/{id}/remediation/proposal   - generate a deterministic
                                                 proposal (requires an approved
                                                 approval request)
POST /api/findings/{id}/remediation/apply      - apply the proposal to the
                                                 workspace repo copy (requires
                                                 explicit ``confirm=true``)
POST /api/findings/{id}/remediation/verify     - re-scan the current snapshot
                                                 and check whether the finding
                                                 is still produced

Errors:
* 404 - finding not found / no remediation record
* 409 - workflow gate failures (missing/non-approved approval, missing
  proposal, no automatic fix, already applied, unconfirmed apply, source
  changed since proposal)
* 500 - code model unavailable (never a fabricated result)
"""

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.remediation.models import RemediationRecord
from app.remediation.service import (
    RemediationGateError,
    RemediationService,
)
from app.remediation.store import get_remediation_store
from app.validate.store import get_finding_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["remediation"])


class ApplyRequest(BaseModel):
    #: Explicit human confirmation. The approval alone never modifies code;
    #: the patch is applied only when the user confirms this exact request.
    confirm: bool


def _service(request: Request) -> RemediationService:
    return RemediationService(request.app.state.settings)


def _require_finding(finding_id: str):
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")
    return finding


def _handle_gate(exc: RemediationGateError) -> HTTPException:
    logger.info("remediation gate rejected: %s", exc)
    return HTTPException(status_code=409, detail=str(exc))


@router.get("/{finding_id}/remediation", response_model=RemediationRecord)
def get_remediation(finding_id: str) -> RemediationRecord:
    record = get_remediation_store().get(finding_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"no remediation record for finding: {finding_id}",
        )
    return record


@router.post(
    "/{finding_id}/remediation/proposal", response_model=RemediationRecord
)
def propose_remediation(finding_id: str, request: Request) -> RemediationRecord:
    _require_finding(finding_id)
    try:
        return _service(request).propose(
            finding_id, request.app.state.session_factory
        )
    except RemediationGateError as exc:
        raise _handle_gate(exc) from exc


@router.post("/{finding_id}/remediation/apply", response_model=RemediationRecord)
def apply_remediation(
    finding_id: str, body: ApplyRequest, request: Request
) -> RemediationRecord:
    _require_finding(finding_id)
    try:
        return _service(request).apply(
            finding_id,
            confirmed=body.confirm,
            session_factory=request.app.state.session_factory,
        )
    except RemediationGateError as exc:
        raise _handle_gate(exc) from exc


@router.post("/{finding_id}/remediation/verify", response_model=RemediationRecord)
def verify_remediation(finding_id: str, request: Request) -> RemediationRecord:
    _require_finding(finding_id)
    try:
        return _service(request).verify(
            finding_id, request.app.state.session_factory
        )
    except RemediationGateError as exc:
        raise _handle_gate(exc) from exc
    except Exception as exc:  # noqa: BLE001 - code model / scan boundary
        logger.exception("remediation verify failed for finding %s", finding_id)
        raise HTTPException(status_code=500, detail="remediation verify failed") from exc