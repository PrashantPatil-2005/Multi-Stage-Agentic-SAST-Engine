"""Cross-repository deduplication API endpoints.

POST /api/deduplicate                 - group findings (by id) into groups
GET  /api/deduplication/{fingerprint} - fetch one deduplication group

``POST /api/deduplicate`` accepts an optional ``scan_run_id`` (Phase 14J):
when present, the run must exist AND its explicit lineage must produce every
submitted finding (404/400 otherwise), and the DEDUPLICATE stage of that run
is recorded as an explicit execution. Clients that omit ``scan_run_id`` are
unchanged - deduplication still runs, with no stage record.

Missing finding ids return 404 with the offending ids listed.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.models import User
from app.auth.rbac import Permission, require_permission
from app.dedup.models import DeduplicationGroup, DeduplicationResult
from app.dedup.service import DeduplicationService, lookup_group
from app.scan.run_models import STAGE_DEDUPLICATE
from app.scan.run_service import (
    StageContextError,
    record_stage_execution,
    validate_stage_context_for_findings,
)
from app.validate.store import get_finding_store

router = APIRouter(tags=["dedup"])


class DedupRequest(BaseModel):
    finding_ids: list[str]
    scan_run_id: str | None = None


@router.post("/deduplicate", response_model=DeduplicationResult)
def deduplicate_findings(
    body: DedupRequest,
    user: User = Depends(require_permission(Permission.DEDUPLICATE)),
) -> DeduplicationResult:
    store = get_finding_store()
    missing = [fid for fid in body.finding_ids if store.get(fid) is None]
    if missing:
        raise HTTPException(
            status_code=404, detail=f"findings not found: {missing}"
        )
    findings = [store.get(fid) for fid in body.finding_ids]

    if body.scan_run_id is not None:
        try:
            validate_stage_context_for_findings(body.scan_run_id, body.finding_ids)
        except StageContextError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail)
        return record_stage_execution(
            body.scan_run_id,
            STAGE_DEDUPLICATE,
            lambda: DeduplicationService().deduplicate(findings),
        )
    return DeduplicationService().deduplicate(findings)


@router.get("/deduplication/{fingerprint}", response_model=DeduplicationGroup)
def get_deduplication_group(
    fingerprint: str,
    user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> DeduplicationGroup:
    group = lookup_group(fingerprint)
    if group is None:
        raise HTTPException(
            status_code=404, detail=f"no deduplication group for: {fingerprint}"
        )
    return group