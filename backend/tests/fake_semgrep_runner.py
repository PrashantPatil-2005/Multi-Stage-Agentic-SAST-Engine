"""Fake Semgrep runner for benchmark tests.

Produces canned results so the benchmark can be exercised without Semgrep
installed. Fake findings are only used inside tests — the real service never
presents fake findings as real results.
"""

from pathlib import Path

from app.benchmark.models import BenchmarkFinding, BenchmarkResult


class FakeSemgrepRunner:
    def __init__(
        self,
        available: bool = True,
        findings: list[BenchmarkFinding] | None = None,
        error: str | None = None,
        duration_ms: int | None = 120,
    ) -> None:
        self._available = available
        self._findings = list(findings or [])
        self._error = error
        self._duration_ms = duration_ms
        self.calls: list[Path] = []

    def is_available(self) -> bool:
        return self._available

    def run(self, target: Path) -> BenchmarkResult:
        self.calls.append(target)
        if not self._available:
            return BenchmarkResult(
                tool="semgrep",
                available=False,
                findings=[],
                duration_ms=None,
                error="semgrep CLI not installed; benchmark unavailable",
            )
        return BenchmarkResult(
            tool="semgrep",
            available=True,
            findings=self._findings,
            duration_ms=self._duration_ms,
            error=self._error,
        )


def finding(
    tool: str = "semgrep",
    vulnerability_type: str = "sql_injection",
    file: str = "app.py",
    line: int = 12,
    function: str | None = "get_user",
    message: str = "finding",
    fingerprint: str | None = None,
) -> BenchmarkFinding:
    return BenchmarkFinding(
        tool=tool,
        vulnerability_type=vulnerability_type,
        file=file,
        line=line,
        function=function,
        message=message,
        fingerprint=fingerprint or f"{tool}|{vulnerability_type}|{file}|{line}",
    )