"""Cross-repository finding deduplication service.

Grouping is fingerprint -> bucket (a single dict pass over the findings), so
the runtime is O(n) in the number of findings - no pairwise comparison.

The service never deletes findings and never mutates a
:class:`CandidateFinding`; every input finding survives inside exactly one
group (``member_finding_ids``), and the canonical finding is simply the
group member with the lexicographically smallest finding id (deterministic).
"""

import logging
from pathlib import Path

from app.dedup.fingerprint import FindingFingerprintBuilder
from app.dedup.models import (
    DeduplicationGroup,
    DeduplicationResult,
    FindingFingerprint,
)
from app.scan.models import CandidateFinding

logger = logging.getLogger(__name__)

#: Every grouped finding matches on all of these - they explain the grouping.
MATCH_REASONS = [
    "same vulnerability type",
    "same source category",
    "same sink category",
    "same normalized source pattern",
    "same normalized sink pattern",
    "same normalized taint structure",
]


def repo_label_for_file(path: str) -> str:
    """Best-effort repository label derived from a finding's file path.

    Findings do not carry a repository id, so the label is approximated:
    the parent directory name for nested paths, otherwise the file name.
    """
    parts = Path(path).parts
    if not parts:
        return "unknown"
    if len(parts) >= 2:
        return parts[-2]
    return parts[-1]


class DeduplicationService:
    def __init__(
        self, builder: FindingFingerprintBuilder | None = None
    ) -> None:
        self._builder = builder or FindingFingerprintBuilder()

    def deduplicate(
        self, findings: list[CandidateFinding]
    ) -> DeduplicationResult:
        buckets: dict[str, tuple[FindingFingerprint, list[CandidateFinding]]] = {}
        for finding in findings:
            fingerprint = self._builder.build(finding)
            bucket = buckets.get(fingerprint.value)
            if bucket is None:
                buckets[fingerprint.value] = (fingerprint, [finding])
            else:
                bucket[1].append(finding)

        groups: list[DeduplicationGroup] = []
        registry: dict[str, DeduplicationGroup] = {}
        for value, (fingerprint, members) in buckets.items():
            ordered = sorted(members, key=lambda f: f.id)
            canonical = ordered[0]
            group = DeduplicationGroup(
                fingerprint=value,
                structural_signature=fingerprint.structural_signature,
                canonical_finding_id=canonical.id,
                member_finding_ids=[f.id for f in ordered],
                occurrence_count=len(ordered),
                repositories=sorted(
                    {repo_label_for_file(f.source.file) for f in ordered}
                ),
                vulnerability_type=fingerprint.vulnerability_type,
                representative_finding=canonical,
                match_reasons=list(MATCH_REASONS),
            )
            groups.append(group)
            registry[value] = group
            logger.info(
                "dedup group: %s count=%d canonical=%s (%s)",
                fingerprint.vulnerability_type,
                len(ordered),
                canonical.id[:12],
                fingerprint.structural_signature,
            )

        _GROUPS.clear()
        _GROUPS.update(registry)
        return DeduplicationResult(
            total_findings=len(findings),
            unique_findings=len(groups),
            duplicate_findings=len(findings) - len(groups),
            groups=groups,
        )


#: In-memory registry of the most recent run, keyed by fingerprint.
#: Used by the API (GET /api/deduplication/{fingerprint}); no persistence yet.
_GROUPS: dict[str, DeduplicationGroup] = {}


def lookup_group(fingerprint: str) -> DeduplicationGroup | None:
    return _GROUPS.get(fingerprint)


def reset_groups() -> None:
    _GROUPS.clear()