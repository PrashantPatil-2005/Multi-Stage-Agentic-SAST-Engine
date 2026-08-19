"""Read-only findings endpoints.

GET /api/findings            - enumerate candidate findings enriched with the
                               available risk, SLA, validation, proof and
                               approval records from the in-memory stores.
                               Optional ``project_id`` scopes the result to
                               findings owned by one project (resolved via the
                               explicit scan lineage; 404 for an unknown
                               project - never a silent global fallback).
GET /api/findings/{id}       - the complete read-only story of one finding,
                               composing the same stores plus dedup membership
                               and authoritative lineage (owning project +
                               producing scan runs).
Nothing is mutated; both endpoints are intentionally read-only.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth.dependencies import get_current_user
from app.auth.models import User

from app.api.findings_models import (
    FindingDetail,
    FindingDedupDetail,
    FindingListItem,
    FindingProject,
    FindingProofDetail,
    FindingSlaDetail,
    FindingSlaInfo,
)
from app.approval.store import get_approval_store
from app.db.models import Project
from app.dedup.service import all_groups, repo_label_for_file
from app.prove.store import get_proof_store
from app.remediation.store import get_remediation_store
from app.risk.service import (
    all_risk_assessments,
    all_sla_records,
    get_risk_assessment,
    get_sla_record,
)
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store, get_validation_store

router = APIRouter(prefix="/findings", tags=["findings"])


def _sla_info(finding_id: str, now: datetime) -> FindingSlaInfo:
    record = all_sla_records()
    sla = next((r for r in record if r.finding_id == finding_id), None)
    if sla is None:
        return FindingSlaInfo(
            status="none", remaining_seconds=None, priority=None
        )
    remaining_seconds = None
    if sla.status == "active" and sla.due_at is not None:
        remaining_seconds = max(0, int((sla.due_at - now).total_seconds()))
    return FindingSlaInfo(
        status=sla.status,
        remaining_seconds=remaining_seconds,
        priority=sla.priority,
    )


def _scoped_findings(request: Request, project_id: str | None) -> list:
    """Resolve which candidate findings to list.

    Unscoped: every registered finding. Scoped: only findings owned by the
    project, where ownership is the persisted relationship
    project -> scan_run -> finding (explicit lineage). An unknown project is
    a 404 - callers must never fall back to the global list.
    """
    if project_id is None:
        return get_finding_store().all()
    with request.app.state.session_factory() as session:
        if session.get(Project, project_id) is None:
            raise HTTPException(
                status_code=404, detail=f"project not found: {project_id}"
            )
    run_store = get_scan_run_store()
    finding_ids: set[str] = set()
    for run in run_store.runs_for_project(project_id):
        finding_ids.update(run_store.finding_ids_for_run(run.scan_run_id))
    return [f for f in get_finding_store().all() if f.id in finding_ids]


def _list_items(findings: list) -> list[FindingListItem]:
    """Enrich candidate findings into list rows (shared by both scopes)."""
    if not findings:
        return []

    proofs = {p.finding_id: p for p in get_proof_store().all()}
    risks = {r.finding_id: r for r in all_risk_assessments()}
    validations = {v.finding_id: v for v in get_validation_store().all()}
    approval_store = get_approval_store()
    now = datetime.now(timezone.utc)

    items: list[FindingListItem] = []
    for finding in sorted(findings, key=lambda f: f.id):
        assessment = risks.get(finding.id)
        validation = validations.get(finding.id)
        proof = proofs.get(finding.id)
        approval = approval_store.find_for_finding(finding.id)
        items.append(
            FindingListItem(
                finding_id=finding.id,
                vulnerability_type=finding.vulnerability_type,
                severity=finding.severity,
                scanner_confidence=finding.confidence,
                priority=assessment.priority if assessment else None,
                risk_score=assessment.risk_score if assessment else None,
                repository=repo_label_for_file(finding.source.file),
                file=finding.source.file,
                source_snippet=finding.source.snippet,
                sink_snippet=finding.sink.snippet,
                source_kind=finding.source.kind,
                sink_kind=finding.sink.kind,
                verdict=validation.verdict if validation else None,
                validation_confidence=(
                    validation.confidence if validation else None
                ),
                validated_at=validation.validated_at if validation else None,
                proof_status=proof.status if proof else None,
                approval_status=approval.status if approval else None,
                sla=_sla_info(finding.id, now),
            )
        )
    return items


def _matches_search(item: FindingListItem, query: str) -> bool:
    """Check whether a finding list item matches a free-text search query.

    Searches across finding_id, vulnerability_type, file, repository,
    source/sink snippets and kinds, and severity/priority.
    """
    haystack = " ".join([
        item.finding_id,
        item.vulnerability_type,
        item.file,
        item.repository or "",
        item.source_snippet,
        item.sink_snippet,
        item.source_kind,
        item.sink_kind,
        item.severity,
        item.priority or "",
    ]).lower()
    return query in haystack


@router.get("", response_model=list[FindingListItem])
def list_findings(
    request: Request,
    project_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    user: User = Depends(get_current_user),
) -> list[FindingListItem]:
    """Enumerate findings, optionally scoped to one project's lineage.

    When ``search`` is provided only findings whose enriched list row
    matches the query (case-insensitive substring across id, vulnerability
    type, file, repository, snippets, severity, priority) are returned.
    """
    items = _list_items(_scoped_findings(request, project_id))
    if search is not None:
        query = search.strip().lower()
        if query:
            items = [item for item in items if _matches_search(item, query)]
    return items


def _sla_detail(finding_id: str, now: datetime) -> FindingSlaDetail | None:
    record = get_sla_record(finding_id)
    if record is None:
        return None
    remaining_seconds = None
    if record.status == "active" and record.due_at is not None:
        remaining_seconds = max(0, int((record.due_at - now).total_seconds()))
    return FindingSlaDetail(
        status=record.status,
        priority=record.priority,
        started_at=record.started_at,
        due_at=record.due_at,
        breached_at=record.breached_at,
        resolved_at=record.resolved_at,
        escalation_level=record.escalation_level,
        remaining_seconds=remaining_seconds,
    )


def _proof_detail(finding_id: str) -> FindingProofDetail | None:
    proof = get_proof_store().get(finding_id)
    if proof is None:
        return None
    policy = proof.sandbox_policy.model_dump() if proof.sandbox_policy else None
    return FindingProofDetail(
        status=proof.status,
        confidence=proof.confidence,
        summary=proof.summary,
        created_at=proof.created_at,
        duration_ms=proof.duration_ms,
        error=proof.error,
        sandbox_policy=policy,
    )


def _dedup_detail(finding_id: str) -> FindingDedupDetail | None:
    group = next(
        (g for g in all_groups() if finding_id in g.member_finding_ids), None
    )
    if group is None:
        return None
    return FindingDedupDetail(
        fingerprint=group.fingerprint,
        structural_signature=group.structural_signature,
        is_canonical=group.canonical_finding_id == finding_id,
        canonical_finding_id=group.canonical_finding_id,
        occurrence_count=group.occurrence_count,
        related_finding_ids=[
            member
            for member in group.member_finding_ids
            if member != finding_id
        ],
    )


def _finding_project(request: Request, project_ids: list[str]) -> FindingProject | None:
    """Authoritative owning project from the finding's explicit lineage.

    Finding ids are project-scoped, so all lineage records share one
    project; when that invariant somehow breaks, report the lineage as
    unavailable instead of guessing (never derived from paths).
    """
    if len(project_ids) != 1:
        return None
    with request.app.state.session_factory() as session:
        row = session.get(Project, project_ids[0])
    if row is None:
        return None
    return FindingProject(
        project_id=row.id,
        name=row.name,
        source_type=row.source_type,
        location=row.location,
        language=row.language,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding_detail(
    finding_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> FindingDetail:
    finding = get_finding_store().get(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"finding not found: {finding_id}")

    run_store = get_scan_run_store()
    runs = run_store.runs_for_finding(finding_id)
    project_ids = sorted({run.project_id for run in runs})

    assessment = get_risk_assessment(finding_id)
    validation = get_validation_store().get(finding_id)
    approval = get_approval_store().find_for_finding(finding_id)
    now = datetime.now(timezone.utc)

    return FindingDetail(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        scanner_confidence=finding.confidence,
        status=finding.status,
        repository=repo_label_for_file(finding.source.file),
        source=finding.source,
        sink=finding.sink,
        taint_path=finding.taint_path,
        risk=assessment,
        sla=_sla_detail(finding_id, now),
        validation=validation,
        proof=_proof_detail(finding_id),
        approval=approval,
        dedup=_dedup_detail(finding_id),
        remediation=get_remediation_store().get(finding_id),
        project=_finding_project(request, project_ids),
        scan_runs=runs,
    )
