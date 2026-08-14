"""Benchmark service (optional evaluation path — never part of the scan pipeline).

Runs our SAST engine and (when installed) Semgrep against the SAME controlled
fixture and produces a comparable report with ground-truth metrics.

Our scanner's findings are converted with a read-only adapter: CandidateFinding
objects are never modified.
"""

import hashlib
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.benchmark.ground_truth import (
    KNOWN_FIXTURES,
    GroundTruthCase,
    get_ground_truth,
    safe_cases,
)
from app.benchmark.matcher import BenchmarkMatcher
from app.benchmark.metrics import compute_metrics
from app.benchmark.models import (
    BenchmarkComparison,
    BenchmarkFinding,
    BenchmarkReport,
    BenchmarkResult,
)
from app.benchmark.semgrep_runner import SemgrepRunner
from app.core.contracts import CodeModel
from app.prepare.parser import PythonASTParser
from app.scan.models import CandidateFinding
from app.scan.service import ScanService

logger = logging.getLogger(__name__)

_FIXTURES_ROOT = Path(
    os.environ.get("SAST_BENCHMARK_FIXTURES_DIR", "")
    or (Path(__file__).resolve().parents[2] / "tests" / "fixtures")
)

_FUNCTION_NAME_RE = re.compile(r"def\s+(\w+)")


def to_benchmark_finding(finding: CandidateFinding) -> BenchmarkFinding:
    """Read-only adapter: CandidateFinding -> BenchmarkFinding (never mutates)."""
    function = None
    snippet = finding.source.snippet
    if isinstance(snippet, str):
        match = _FUNCTION_NAME_RE.search(snippet)
        if match:
            function = match.group(1)
    fingerprint_source = "|".join(
        [
            finding.vulnerability_type,
            finding.source.file,
            str(finding.source.line),
            function or "",
            finding.sink.snippet,
        ]
    )
    return BenchmarkFinding(
        tool="our-sast",
        vulnerability_type=finding.vulnerability_type,
        file=finding.source.file,
        line=finding.source.line,
        function=function,
        message=(
            f"{finding.vulnerability_type}: {finding.sink.snippet} "
            f"(source {finding.source.kind} at line {finding.source.line})"
        ),
        fingerprint=hashlib.sha256(
            fingerprint_source.encode("utf-8")
        ).hexdigest(),
    )


class UnknownFixtureError(ValueError):
    pass


class InvalidFixtureNameError(ValueError):
    pass


_REPORTS: dict[str, BenchmarkReport] = {}


def get_report(benchmark_id: str) -> BenchmarkReport | None:
    """Shared report store (module-level, same convention as other stages)."""
    return _REPORTS.get(benchmark_id)


def clear_reports() -> None:
    _REPORTS.clear()


class BenchmarkService:
    def __init__(
        self,
        runner: SemgrepRunner | None = None,
        matcher: BenchmarkMatcher | None = None,
        fixtures_root: Path | None = None,
    ) -> None:
        self._runner = runner if runner is not None else SemgrepRunner()
        self._matcher = matcher or BenchmarkMatcher()
        self._fixtures_root = Path(fixtures_root) if fixtures_root else _FIXTURES_ROOT

    # -------------------------------------------------------------- fixtures

    def resolve_fixture(self, fixture: str) -> Path:
        if not fixture or not re.fullmatch(r"[A-Za-z0-9_]+", fixture):
            raise InvalidFixtureNameError(
                "fixture name may only contain letters, digits and underscores"
            )
        path = (self._fixtures_root / fixture).resolve()
        if not path.is_dir():
            raise UnknownFixtureError(f"unknown fixture: {fixture}")
        return path

    # ------------------------------------------------------------------ scan

    def _scan_fixture(self, fixture_dir: Path) -> list[CandidateFinding]:
        parser = PythonASTParser()
        model = CodeModel(
            language="python",
            files=[
                parser.parse(path.name, path.read_text(encoding="utf-8"))
                for path in sorted(fixture_dir.rglob("*.py"))
                if not any(
                    part in {"__pycache__", "node_modules", ".venv", "venv", ".git"}
                    for part in path.parts
                )
            ],
            module_map={},
            function_index=[],
            built_at=datetime.now(timezone.utc),
        )
        return ScanService().scan(model).findings

    # ------------------------------------------------------------------- run

    def run(self, fixture: str) -> BenchmarkReport:
        fixture_dir = self.resolve_fixture(fixture)
        cases = get_ground_truth(fixture)
        benchmark_id = hashlib.sha256(
            f"{fixture}|{datetime.now(timezone.utc).isoformat()}|{uuid.uuid4().hex}"
            .encode("utf-8")
        ).hexdigest()[:32]

        started = time.monotonic()
        ours = [to_benchmark_finding(f) for f in self._scan_fixture(fixture_dir)]
        our_duration = int((time.monotonic() - started) * 1000)
        our_result = BenchmarkResult(
            tool="our-sast",
            available=True,
            findings=ours,
            duration_ms=our_duration,
            error=None,
        )

        semgrep_result = self._runner.run(fixture_dir)

        comparison = self._build_comparison(ours, semgrep_result.findings, cases)

        metrics = [compute_metrics("our-sast", ours, fixture, self._matcher)]
        if semgrep_result.available:
            metrics.append(
                compute_metrics("semgrep", semgrep_result.findings, fixture, self._matcher)
            )

        report = BenchmarkReport(
            benchmark_id=benchmark_id,
            fixture=fixture,
            ground_truth_count=len(cases),
            our_result=our_result,
            semgrep_result=semgrep_result,
            metrics=metrics,
            comparison=comparison,
            created_at=datetime.now(timezone.utc),
        )
        _REPORTS[benchmark_id] = report
        logger.info(
            "benchmark: %s ours=%d semgrep=%s duration=%dms",
            benchmark_id[:12],
            len(ours),
            semgrep_result.available,
            (time.monotonic() - started) * 1000,
        )
        return report

    def _build_comparison(
        self,
        ours: list[BenchmarkFinding],
        theirs: list[BenchmarkFinding],
        cases: list[GroundTruthCase],
    ) -> BenchmarkComparison:
        if not theirs:
            return BenchmarkComparison(
                ours_only=list(ours),
                shared_vulnerability_types=sorted(
                    {f.vulnerability_type for f in ours}
                ),
                safe_cases_detected_incorrectly=[],
            )
        shared, ours_only, theirs_only = self._matcher.match_cross_tool(
            ours, theirs
        )
        safe_incorrect = sorted(
            {
                case.case_id
                for case in cases
                if not case.expected_vulnerable
                and any(
                    self._matcher.matches_case(f, case)
                    for f in list(ours) + list(theirs)
                )
            }
        )
        return BenchmarkComparison(
            shared_findings=shared,
            ours_only=ours_only,
            semgrep_only=theirs_only,
            shared_vulnerability_types=sorted(
                {f.vulnerability_type for f in shared}
            ),
            safe_cases_detected_incorrectly=safe_incorrect,
        )

    # -------------------------------------------------------------- queries

    def get_report(self, benchmark_id: str) -> BenchmarkReport | None:
        return _REPORTS.get(benchmark_id)

    def clear(self) -> None:
        _REPORTS.clear()