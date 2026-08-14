"""Deduplication output contracts.

A :class:`FindingFingerprint` is the structural identity of a finding: it is
deterministic and independent of repository, file path, line number, finding
id and timestamp, so equivalent vulnerabilities in different repositories
produce the same fingerprint.

A :class:`DeduplicationGroup` collects every finding that shares one
fingerprint; :class:`DeduplicationResult` is the summary of one run.
"""

from pydantic import BaseModel

from app.scan.models import CandidateFinding


class FindingFingerprint(BaseModel):
    """Structural identity of a finding (deterministic, repository-agnostic)."""

    value: str  # SHA-256 of the structural signature (hex digest)
    structural_signature: str  # human-readable, explainable signature
    vulnerability_type: str
    source_category: str
    sink_category: str
    normalized_source: str
    normalized_sink: str
    taint_structure: str  # e.g. "source->string_construction->sink"


class DeduplicationGroup(BaseModel):
    """All findings that share one structural fingerprint."""

    fingerprint: str
    structural_signature: str
    canonical_finding_id: str
    member_finding_ids: list[str]
    occurrence_count: int
    repositories: list[str]
    vulnerability_type: str
    representative_finding: CandidateFinding
    match_reasons: list[str]


class DeduplicationResult(BaseModel):
    """Summary of one deduplication run over a set of findings."""

    total_findings: int
    unique_findings: int
    duplicate_findings: int
    groups: list[DeduplicationGroup]