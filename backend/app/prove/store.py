"""In-memory ProofResult store for the PROVE API (mirrors validate/store.py)."""

from app.prove.models import ProofResult


class ProofStore:
    def __init__(self) -> None:
        self._results: dict[str, ProofResult] = {}

    def record(self, result: ProofResult) -> None:
        self._results[result.finding_id] = result

    def get(self, finding_id: str) -> ProofResult | None:
        return self._results.get(finding_id)

    def clear(self) -> None:
        self._results.clear()


_proofs = ProofStore()


def get_proof_store() -> ProofStore:
    return _proofs
