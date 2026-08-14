"""SLA deadline policy (configurable).

Default deadlines per priority::

    P0 -> 4 hours
    P1 -> 24 hours
    P2 -> 3 days
    P3 -> 7 days
    P4 -> no SLA (not_applicable)

Custom policies are constructed with an explicit ``deadlines`` mapping.
"""

from dataclasses import dataclass, field
from datetime import timedelta

DEFAULT_DEADLINES: dict[str, timedelta | None] = {
    "P0": timedelta(hours=4),
    "P1": timedelta(hours=24),
    "P2": timedelta(days=3),
    "P3": timedelta(days=7),
    "P4": None,
}


@dataclass(frozen=True)
class SLAPolicy:
    deadlines: dict[str, timedelta | None] = field(
        default_factory=lambda: dict(DEFAULT_DEADLINES)
    )

    def duration_for(self, priority: str) -> timedelta | None:
        return self.deadlines.get(priority)