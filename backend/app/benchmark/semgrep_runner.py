"""Controlled, offline Semgrep CLI runner (benchmark only).

Rules: Semgrep is benchmarked with a repository-independent rule set bundled
with this module (``app/benchmark/rules/``). No registry rules are
downloaded — ``--config auto`` and friends are never used, so the benchmark
has zero network dependency.

Execution: the fixture directory is passed as a *target*, never imported or
executed. The subprocess uses an argument list (never ``shell=True``), a
hard timeout, and a bounded stdout size.

Exit codes: Semgrep returns 0 for "no findings" and 1 for "findings found";
both are normal. Exit codes >= 2 are reported as an error result.
"""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from app.benchmark.models import BenchmarkFinding, BenchmarkResult

RULES_DIR = Path(__file__).parent / "rules"


def _function_name(first_code_line: str) -> str | None:
    match = re.search(r"def\s+(\w+)", first_code_line)
    return match.group(1) if match else None


def _canonical_type(check_id: str) -> str:
    """Map a Semgrep rule id to our canonical vulnerability types."""
    lowered = check_id.lower()
    if "sql" in lowered:
        return "sql_injection"
    if "command" in lowered or "shell" in lowered or "subprocess" in lowered:
        return "command_injection"
    if "ssrf" in lowered or "url" in lowered or "request" in lowered:
        return "ssrf"
    return check_id


def parse_semgrep_json(
    text: str, tool: str = "semgrep"
) -> tuple[list[BenchmarkFinding], str | None]:
    """Parse ``semgrep --json`` output defensively.

    Returns (findings, error). Never raises on malformed input.
    """
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"malformed semgrep JSON: {exc}"

    if not isinstance(payload, dict):
        return [], "malformed semgrep JSON: expected an object"

    findings: list[BenchmarkFinding] = []
    for raw in payload.get("results", []) or []:
        if not isinstance(raw, dict):
            continue
        check_id = str(raw.get("check_id") or "unknown")
        path = str(raw.get("path") or "")
        start = raw.get("start") or {}
        line = start.get("line")
        if not path or not isinstance(line, int):
            continue
        extra = raw.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {}
        message = str(extra.get("message") or check_id)
        lines_text = extra.get("lines") or ""
        function = None
        if isinstance(lines_text, str):
            first_line = lines_text.strip().splitlines()[0] if lines_text.strip() else ""
            function = _function_name(first_line)
        fingerprint_source = "|".join(
            [check_id, path, str(line), str(function), message]
        )
        findings.append(
            BenchmarkFinding(
                tool=tool,
                vulnerability_type=_canonical_type(check_id),
                file=Path(path).name,
                line=line,
                function=function,
                message=message,
                fingerprint=hashlib.sha256(
                    fingerprint_source.encode("utf-8")
                ).hexdigest(),
            )
        )

    errors = payload.get("errors") or []
    return findings, None


class SemgrepRunner:
    """Run the Semgrep CLI in a controlled subprocess (never shell=True)."""

    def __init__(
        self,
        executable: str | None = None,
        rules_dir: Path | None = None,
        timeout_s: int = 30,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        self._executable = executable or "semgrep"
        self._rules_dir = Path(rules_dir) if rules_dir else RULES_DIR
        self._timeout_s = timeout_s
        self._max_output_bytes = max_output_bytes

    def is_available(self) -> bool:
        return shutil.which(self._executable) is not None

    def build_command(self, target: Path) -> list[str]:
        """Trusted argument list; no shell, no network, no registry rules."""
        return [
            self._executable,
            "--json",
            "--config",
            str(self._rules_dir),
            "--timeout",
            str(self._timeout_s),
            str(target),
        ]

    def run(self, target: Path) -> BenchmarkResult:
        """Run Semgrep against a fixture directory; never fails hard."""
        import time

        if not self.is_available():
            return BenchmarkResult(
                tool="semgrep",
                available=False,
                findings=[],
                duration_ms=None,
                error=(
                    "semgrep CLI not installed; benchmark unavailable. "
                    "No fake findings are reported in its place. "
                    "(install semgrep separately to enable this benchmark)"
                ),
            )
        if not self._rules_dir.is_dir():
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                error=f"benchmark rules directory missing: {self._rules_dir}",
            )

        command = self.build_command(target)
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            stdout, stderr = process.communicate(timeout=self._timeout_s)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"semgrep timed out after {self._timeout_s}s",
            )
        except OSError as exc:
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"semgrep failed to start: {exc}",
            )
        finally:
            duration = int((time.monotonic() - started) * 1000)

        if len(stdout) > self._max_output_bytes or len(stderr) > self._max_output_bytes:
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                duration_ms=duration,
                error="semgrep output exceeded size limit; result discarded",
            )

        if process.returncode >= 2:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                duration_ms=duration,
                error=f"semgrep exited with code {process.returncode}: "
                f"{stderr_text[:500]}",
            )

        findings, parse_error = parse_semgrep_json(
            stdout.decode("utf-8", errors="replace")
        )
        if parse_error is not None:
            return BenchmarkResult(
                tool="semgrep",
                available=True,
                findings=[],
                duration_ms=duration,
                error=parse_error,
            )
        return BenchmarkResult(
            tool="semgrep",
            available=True,
            findings=findings,
            duration_ms=duration,
            error=None,
        )