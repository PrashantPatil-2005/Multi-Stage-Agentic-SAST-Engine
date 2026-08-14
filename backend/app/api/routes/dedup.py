"""Cross-repository deduplication API endpoints.

POST /api/deduplicate                 - group findings (by id) into groups
GET  /api/deduplication/{fingerprint} - fetch one deduplication group

Findings are looked up in the existing in-memory finding store (no new
persistence). Missing finding ids return 404 with the offending ids listed.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.dedup.models import DeduplicationGroup, DeduplicationResult
from app.dedup.service import DeduplicationService, lookup_group
from app.validate.store import get_finding_store

router = APIRouter(tags=["dedup"])


class DedupRequest(BaseModel):
    finding_ids: list[str]


@router.post("/deduplicate", response_model=DeduplicationResult)
def deduplicate_findings(request: DedupRequest) -> DeduplicationResult:
    store = get_finding_store()
    missing = [fid for fid in request.finding_ids if store.get(fid) is None]
    if missing:
        raise HTTPException(
            status_code=404, detail=f"findings not found: {missing}"
        )
    findings = [store.get(fid) for fid in request.finding_ids]
    return DeduplicationService().deduplicate(findings)


@router.get("/deduplication/{fingerprint}", response_model=DeduplicationGroup)
def get_deduplication_group(fingerprint: str) -> DeduplicationGroup:
    group = lookup_group(fingerprint)
    if group is None:
        raise HTTPException(
            status_code=404, detail=f"no deduplication group for: {fingerprint}"
        )
    return group