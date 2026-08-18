"""RemediationRecord store with optional SQLite backing.

Mirrors the other pipeline stores (see ``app/db/persistence.py``): in-memory
registry plus SQLite rows when a session factory is configured. Rehydration
on startup restores previously applied/verified remediation state.
"""

from app.db.models import RemediationRow
from app.db.persistence import db_delete, db_delete_all, db_load_all, db_upsert
from app.remediation.models import RemediationRecord


class RemediationStore:
    def __init__(self) -> None:
        self._records: dict[str, RemediationRecord] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._records.clear()
        for key, record in db_load_all(
            factory, RemediationRow, RemediationRecord, "finding_id"
        ):
            self._records[key] = record

    def record(self, record: RemediationRecord) -> None:
        self._records[record.finding_id] = record
        db_upsert(
            self._factory, RemediationRow, "finding_id", record.finding_id, record
        )

    def get(self, finding_id: str) -> RemediationRecord | None:
        return self._records.get(finding_id)

    def all(self) -> list[RemediationRecord]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._records.values())

    def remove(self, finding_id: str) -> None:
        """Remove one record (used by repository deletion)."""
        self._records.pop(finding_id, None)
        db_delete(self._factory, RemediationRow, "finding_id", finding_id)

    def clear(self) -> None:
        self._records.clear()
        db_delete_all(self._factory, RemediationRow)


_remediation = RemediationStore()


def get_remediation_store() -> RemediationStore:
    return _remediation


def set_remediation_store_factory(factory) -> None:
    _remediation.set_factory(factory)