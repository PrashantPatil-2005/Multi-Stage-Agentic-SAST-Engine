"""Cross-repository finding deduplication (post-SCAN, pre-VALIDATE)."""

from app.dedup.fingerprint import FindingFingerprintBuilder, normalize_snippet
from app.dedup.models import (
    DeduplicationGroup,
    DeduplicationResult,
    FindingFingerprint,
)
from app.dedup.service import (
    DeduplicationService,
    lookup_group,
    reset_groups,
)

__all__ = [
    "DeduplicationGroup",
    "DeduplicationResult",
    "DeduplicationService",
    "FindingFingerprint",
    "FindingFingerprintBuilder",
    "lookup_group",
    "normalize_snippet",
    "reset_groups",
]