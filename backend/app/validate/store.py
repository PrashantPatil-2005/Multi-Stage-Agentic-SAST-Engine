"""In-memory stores for the VALIDATE API, with optional SQLite backing.

SCAN findings and validation results are kept in in-memory registries and
mirrored into SQLite rows whenever a session factory is configured (see
``app/db/persistence.py``). Without a factory the stores behave purely
in-memory, so direct-service tests and library usage are unchanged.

``set_validate_store_factory`` is called from the FastAPI lifespan and
rehydrates both stores from the database.
"""

from app.db.models import FindingRow, ValidationResultRow
from app.db.persistence import (
    db_delete,
    db_delete_all,
    db_load_all,
    db_upsert,
)
from app.scan.models import CandidateFinding, ScanReport
from app.validate.models import ValidationResult


class FindingStore:
    """Registry of candidate findings (by id) available for validation."""

    def __init__(self) -> None:
        self._findings: dict[str, CandidateFinding] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._findings.clear()
        for key, finding in db_load_all(
            factory, FindingRow, CandidateFinding, "finding_id"
        ):
            self._findings[key] = finding

    def add_report(self, report: ScanReport) -> None:
        for finding in report.findings:
            self.add(finding)

    def add(self, finding: CandidateFinding) -> None:
        self._findings[finding.id] = finding
        db_upsert(self._factory, FindingRow, "finding_id", finding.id, finding)

    def get(self, finding_id: str) -> CandidateFinding | None:
        return self._findings.get(finding_id)

    def all(self) -> list[CandidateFinding]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._findings.values())

    def remove(self, finding_id: str) -> None:
        """Remove one finding (used by repository deletion)."""
        self._findings.pop(finding_id, None)
        db_delete(self._factory, FindingRow, "finding_id", finding_id)

    def clear(self) -> None:
        self._findings.clear()
        db_delete_all(self._factory, FindingRow)


class ValidationStore:
    """Validation results keyed by finding id (kept separate from findings)."""

    def __init__(self) -> None:
        self._results: dict[str, ValidationResult] = {}
        self._factory = None

    def set_factory(self, factory) -> None:
        self._factory = factory
        self._results.clear()
        for key, result in db_load_all(
            factory, ValidationResultRow, ValidationResult, "finding_id"
        ):
            self._results[key] = result

    def record(self, result: ValidationResult) -> None:
        self._results[result.finding_id] = result
        db_upsert(
            self._factory, ValidationResultRow, "finding_id", result.finding_id, result
        )

    def get(self, finding_id: str) -> ValidationResult | None:
        return self._results.get(finding_id)

    def all(self) -> list[ValidationResult]:
        """Read-only enumeration (used by read/summary endpoints)."""
        return list(self._results.values())

    def remove(self, finding_id: str) -> None:
        """Remove one validation result (used by repository deletion)."""
        self._results.pop(finding_id, None)
        db_delete(self._factory, ValidationResultRow, "finding_id", finding_id)

    def clear(self) -> None:
        self._results.clear()
        db_delete_all(self._factory, ValidationResultRow)


_findings = FindingStore()
_results = ValidationStore()


def get_finding_store() -> FindingStore:
    return _findings


def get_validation_store() -> ValidationStore:
    return _results


def set_validate_store_factory(factory) -> None:
    _findings.set_factory(factory)
    _results.set_factory(factory)