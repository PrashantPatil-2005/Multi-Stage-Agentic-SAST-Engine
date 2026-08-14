"""In-memory stores for the VALIDATE API.

SCAN findings are not persisted; the validation API looks them up through
:class:`FindingStore` and records results in :class:`ValidationStore`.
This is a deliberate service-level abstraction - swap these for real
persistence later without touching the routes.
"""

from app.scan.models import CandidateFinding, ScanReport
from app.validate.models import ValidationResult


class FindingStore:
    """Registry of candidate findings (by id) available for validation."""

    def __init__(self) -> None:
        self._findings: dict[str, CandidateFinding] = {}

    def add_report(self, report: ScanReport) -> None:
        for finding in report.findings:
            self._findings[finding.id] = finding

    def add(self, finding: CandidateFinding) -> None:
        self._findings[finding.id] = finding

    def get(self, finding_id: str) -> CandidateFinding | None:
        return self._findings.get(finding_id)

    def clear(self) -> None:
        self._findings.clear()


class ValidationStore:
    """Validation results keyed by finding id (kept separate from findings)."""

    def __init__(self) -> None:
        self._results: dict[str, ValidationResult] = {}

    def record(self, result: ValidationResult) -> None:
        self._results[result.finding_id] = result

    def get(self, finding_id: str) -> ValidationResult | None:
        return self._results.get(finding_id)

    def clear(self) -> None:
        self._results.clear()


_findings = FindingStore()
_results = ValidationStore()


def get_finding_store() -> FindingStore:
    return _findings


def get_validation_store() -> ValidationStore:
    return _results
