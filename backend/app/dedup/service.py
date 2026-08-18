"""Cross-repository finding deduplication service.

Grouping is fingerprint -> bucket (a single dict pass over the findings), so
the runtime is O(n) in the number of findings - no pairwise comparison.

The service never deletes findings and never mutates a
:class:`CandidateFinding`; every input finding survives inside exactly one
group (``member_finding_ids``), and the canonical finding is simply the
group member with the lexicographically smallest finding id (deterministic).

Runs are incremental and merge across repositories: groups registered by
earlier runs stay in the registry, and a later run over a subset of findings
(e.g. a second repository's scan) joins its members into the existing group
for the same fingerprint. Existing members are re-read from the finding
store, so findings that were deleted (e.g. repository removal) drop out of
their group instead of lingering.
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
from app.validate.store import get_finding_store

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

        submitted_ids = {f.id for f in findings}
        finding_store = get_finding_store()
        next_registry = dict(_GROUPS)
        groups: list[DeduplicationGroup] = []
        for value, (fingerprint, members) in buckets.items():
            existing = next_registry.get(value)
            if existing is not None:
                for member_id in existing.member_finding_ids:
                    if member_id in submitted_ids:
                        continue
                    member = finding_store.get(member_id)
                    if member is not None:
                        members.append(member)
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
            next_registry[value] = group
            logger.info(
                "dedup group: %s count=%d canonical=%s (%s)",
                fingerprint.vulnerability_type,
                len(ordered),
                canonical.id[:12],
                fingerprint.structural_signature,
            )

        _GROUPS.clear()
        _GROUPS.update(next_registry)
        self._persist_groups(next_registry)
        return DeduplicationResult(
            total_findings=len(findings),
            unique_findings=len(groups),
            duplicate_findings=len(findings) - len(groups),
            groups=groups,
        )

    def _persist_groups(self, registry: dict[str, DeduplicationGroup]) -> None:
        from app.db.models import DeduplicationGroupRow
        from app.db.persistence import db_delete_all, db_insert

        db_delete_all(_factory, DeduplicationGroupRow)
        for group in registry.values():
            db_insert(
                _factory,
                DeduplicationGroupRow(
                    fingerprint=group.fingerprint,
                    payload=group.model_dump(mode="json"),
                ),
            )


#: In-memory registry of the most recent run, keyed by fingerprint.
#: Used by the API (GET /api/deduplication/{fingerprint}); persisted to
#: SQLite when a session factory is configured (app/db/persistence.py).
_GROUPS: dict[str, DeduplicationGroup] = {}
_factory = None


def set_dedup_store_factory(factory) -> None:
    """Rehydrate the dedup group registry from the database (lifespan)."""
    from app.db.models import DeduplicationGroupRow
    from app.db.persistence import db_load_all

    global _factory
    _factory = factory
    _GROUPS.clear()
    for key, group in db_load_all(
        factory, DeduplicationGroupRow, DeduplicationGroup, "fingerprint"
    ):
        _GROUPS[key] = group


def lookup_group(fingerprint: str) -> DeduplicationGroup | None:
    return _GROUPS.get(fingerprint)


def remove_findings(finding_ids: set[str]) -> None:
    """Drop deleted findings from the current group registry.

    Used by repository deletion: a deleted repository's findings must not
    stay listed as group members. Affected groups are rebuilt from the
    remaining member findings (canonical = smallest remaining id); groups
    with no remaining members are removed outright. Idempotent - findings
    that never were grouped are fine.
    """
    from app.db.models import DeduplicationGroupRow
    from app.db.persistence import db_delete_all, db_insert
    from app.validate.store import get_finding_store

    finding_store = get_finding_store()
    changed = False
    for fingerprint, group in list(_GROUPS.items()):
        remaining = [
            fid for fid in group.member_finding_ids if fid not in finding_ids
        ]
        if len(remaining) == len(group.member_finding_ids):
            continue
        changed = True
        if not remaining:
            del _GROUPS[fingerprint]
            continue
        members = [
            finding
            for fid in remaining
            if (finding := finding_store.get(fid)) is not None
        ]
        if not members:
            del _GROUPS[fingerprint]
            continue
        members.sort(key=lambda f: f.id)
        canonical = members[0]
        _GROUPS[fingerprint] = group.model_copy(
            update={
                "canonical_finding_id": canonical.id,
                "member_finding_ids": [f.id for f in members],
                "occurrence_count": len(members),
                "repositories": sorted(
                    {repo_label_for_file(f.source.file) for f in members}
                ),
                "representative_finding": canonical,
            }
        )
    if not changed:
        return
    db_delete_all(_factory, DeduplicationGroupRow)
    for group in _GROUPS.values():
        db_insert(
            _factory,
            DeduplicationGroupRow(
                fingerprint=group.fingerprint,
                payload=group.model_dump(mode="json"),
            ),
        )


def all_groups() -> list[DeduplicationGroup]:
    """Read-only enumeration (used by read/summary endpoints)."""
    return list(_GROUPS.values())


def reset_groups() -> None:
    from app.db.models import DeduplicationGroupRow
    from app.db.persistence import db_delete_all

    _GROUPS.clear()
    db_delete_all(_factory, DeduplicationGroupRow)