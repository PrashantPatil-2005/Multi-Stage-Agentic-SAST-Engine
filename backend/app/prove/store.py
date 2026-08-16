"""ProofResult store for the PROVE API with optional SQLite backing.

Mirrors validate/store.py: in-memory registry plus SQLite rows when a
session factory is configured (see ``app/db/persistence.py``).
"""

from app.db.models import ProofResultRow
from app.db.persistence import db_delete, db_delete_all, db_load_all, db_upsert
from app.prove.models import ProofResult


class ProofStore:
    def __init__(self) -> None:
        self._results: dict[str, ProofResult] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._results.clear()
        for key, result in db_load_all(factory, ProofResultRow, ProofResult, "finding_id"):
            self._results[key] = result

    def record(self, result: ProofResult) -> None:
        self._results[result.finding_id] = result
        db_upsert(self._factory, ProofResultRow, "finding_id", result.finding_id, result)

    def get(self, finding_id: str) -> ProofResult | None:
        return self._results.get(finding_id)

    def all(self) -> list[ProofResult]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._results.values())

    def remove(self, finding_id: str) -> None:
        """Remove one proof result (used by repository deletion)."""
        self._results.pop(finding_id, None)
        db_delete(self._factory, ProofResultRow, "finding_id", finding_id)

    def clear(self) -> None:
        self._results.clear()
        db_delete_all(self._factory, ProofResultRow)


_proofs = ProofStore()


def get_proof_store() -> ProofStore:
    return _proofs


def set_proof_store_factory(factory) -> None:
    _proofs.set_factory(factory)