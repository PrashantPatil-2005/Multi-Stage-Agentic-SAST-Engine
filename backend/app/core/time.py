"""Timezone-safe datetime helpers shared across pipeline stages.

All stages create timestamps with ``datetime.now(timezone.utc)`` (aware).
Records persisted before that convention can hold naive ISO datetimes in
their JSON payloads; on rehydration (app/db/persistence.py) pydantic keeps
them naive. Any sort/compare that mixes the two raises ``TypeError``, so
read paths normalize with :func:`as_aware_utc` before ordering.
"""

from datetime import datetime, timezone


def as_aware_utc(value: datetime) -> datetime:
    """Return ``value`` as an aware UTC datetime (naive input assumed UTC)."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
