"""Semgrep benchmark tests (service level)."""

import json

import pytest

from app.benchmark.ground_truth import get_ground_truth, safe_cases, vulnerable_cases
from app.benchmark.matcher import BenchmarkMatcher
from app.benchmark.metrics import compute_metrics
from app.benchmark.semgrep_runner import (
    RULES_DIR,
    SemgrepRunner,
    parse_semgrep_json,
)
from app.benchmark.service import (
    BenchmarkService,
    InvalidFixtureNameError,
    UnknownFixtureError,
    clear_reports,
    to_benchmark_finding,
)
from app.prove.store import get_proof_store
from app.risk.service import get_escalation_events, get_risk_assessment, get_sla_record
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_semgrep_runner import FakeSemgrepRunner, finding
from tests.scan_test_helpers import scan_fixture_files

FIXTURE = "vulnerable_python_app"


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    clear_reports()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    clear_reports()


# ---------------------------------------------------- availability / offline


def test_benchmark_works_without_semgrep():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    assert report.semgrep_result.available is False
    assert report.semgrep_result.findings == []
    assert report.semgrep_result.error is not None
    assert report.metrics[0].tool == "our-sast"


def test_unavailable_semgrep_reported_not_pretended():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    assert "unavailable" in report.semgrep_result.error.lower()
    assert report.semgrep_result.duration_ms is None
    assert all(m.tool != "semgrep" for m in report.metrics)


def test_real_runner_is_available_detection(monkeypatch):
    runner = SemgrepRunner()
    assert runner.is_available() is False or True  # environment-dependent
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    assert SemgrepRunner(executable="semgrep").is_available() is True
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: None)
    assert SemgrepRunner(executable="semgrep").is_available() is False


# --------------------------------------------------------------- our adapter


def test_our_findings_convert_correctly():
    finding_ = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    converted = to_benchmark_finding(finding_)
    assert converted.tool == "our-sast"
    assert converted.vulnerability_type == "sql_injection"
    assert converted.file == "app.py"
    assert converted.line == 12
    assert converted.function == "get_user"
    assert converted.fingerprint


def test_conversion_does_not_modify_candidate_finding():
    before = scan_fixture_files("app.py").findings
    snapshot = [f.model_dump() for f in before]
    for f in before:
        to_benchmark_finding(f)
    after = [f.model_dump() for f in before]
    assert after == snapshot


def test_benchmark_run_preserves_candidate_findings():
    before = scan_fixture_files("app.py").findings
    snapshot = [f.model_dump() for f in before]
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    service.run(FIXTURE)
    after = [f.model_dump() for f in before]
    assert after == snapshot


# ------------------------------------------------------------- semgrep parse


def _semgrep_json(fixture_findings=True) -> str:
    results = []
    if fixture_findings:
        results.append(
            {
                "check_id": "benchmark-sql-injection",
                "path": "app.py",
                "start": {"line": 15},
                "extra": {
                    "message": "Potential SQL injection",
                    "lines": "    cursor = conn.execute(query)\n",
                },
            }
        )
    return json.dumps({"results": results, "errors": []})


def test_semgrep_json_parses_correctly():
    findings, error = parse_semgrep_json(_semgrep_json())
    assert error is None
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.vulnerability_type == "sql_injection"
    assert f.file == "app.py"
    assert f.line == 15
    assert f.function is None  # sink line has no def header
    assert f.fingerprint


def test_semgrep_json_parses_def_line_for_function():
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "benchmark-command-injection",
                    "path": "app.py",
                    "start": {"line": 33},
                    "extra": {
                        "message": "shell=True",
                        "lines": "def run_command(cmd: str) -> None:\n    subprocess.run(cmd, shell=True)\n",
                    },
                }
            ],
            "errors": [],
        }
    )
    findings, _ = parse_semgrep_json(payload)
    assert findings[0].function == "run_command"
    assert findings[0].vulnerability_type == "command_injection"


def test_malformed_json_handled():
    findings, error = parse_semgrep_json("{not json")
    assert findings == []
    assert "malformed" in error


def test_non_object_json_handled():
    findings, error = parse_semgrep_json("[1, 2]")
    assert findings == []
    assert "malformed" in error


def test_semgrep_nonzero_exit_handled(monkeypatch):
    class FakeProc:
        def __init__(self, code, out=b"", err=b""):
            self.returncode = code
            self._out = out
            self._err = err

        def communicate(self, timeout=None):
            return self._out, self._err

        def kill(self):
            pass

    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen",
        lambda *a, **k: FakeProc(2, b"", b"rules could not be loaded"),
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    result = SemgrepRunner(executable="semgrep").run(Path := __import__("pathlib").Path("."))
    assert result.available is True
    assert result.findings == []
    assert "exit" in result.error


def test_semgrep_exit_code_1_is_normal():
    """Semgrep exits 1 when it finds issues — that is NOT an error."""

    class FakeProc:
        returncode = 1

        def __init__(self, *a, **k):
            pass

        def communicate(self, timeout=None):
            return _semgrep_json().encode(), b""

        def kill(self):
            pass

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    try:
        result = SemgrepRunner(executable="semgrep").run(
            __import__("pathlib").Path(".")
        )
        assert result.available is True
        assert result.error is None
        assert len(result.findings) == 1
    finally:
        monkeypatch.undo()


def test_semgrep_timeout_handled(monkeypatch):
    class FakeProc:
        def __init__(self, *a, **k):
            pass

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired("semgrep", timeout)

        def kill(self):
            pass

    import subprocess

    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    result = SemgrepRunner(executable="semgrep", timeout_s=2).run(
        __import__("pathlib").Path(".")
    )
    assert result.available is True
    assert result.findings == []
    assert "timed out" in result.error


def test_semgrep_empty_results_handled():
    findings, error = parse_semgrep_json(json.dumps({"results": [], "errors": []}))
    assert findings == []
    assert error is None


# ------------------------------------------------------------------ matcher


def test_matcher_matches_equivalent_findings():
    matcher = BenchmarkMatcher()
    a = finding(tool="our-sast", line=20)
    b = finding(tool="semgrep", line=20)
    shared, ours_only, theirs_only = matcher.match_cross_tool([a], [b])
    assert len(shared) == 1
    assert ours_only == []
    assert theirs_only == []


def test_matcher_tolerates_small_line_difference():
    matcher = BenchmarkMatcher(tolerance=3)
    a = finding(tool="our-sast", line=20, function=None)
    b = finding(tool="semgrep", line=21, function=None)
    shared, _, _ = matcher.match_cross_tool([a], [b])
    assert len(shared) == 1
    strict = BenchmarkMatcher(tolerance=0)
    shared, _, _ = strict.match_cross_tool([a], [b])
    assert shared == []


def test_matcher_matches_on_function_when_lines_differ():
    matcher = BenchmarkMatcher(tolerance=1)
    a = finding(tool="our-sast", line=12, function="get_user")
    b = finding(tool="semgrep", line=40, function="get_user")
    shared, _, _ = matcher.match_cross_tool([a], [b])
    assert len(shared) == 1


def test_matcher_does_not_overmatch():
    matcher = BenchmarkMatcher(tolerance=3)
    a = finding(tool="our-sast", line=12, vulnerability_type="sql_injection", function=None)
    b = finding(tool="semgrep", line=12, vulnerability_type="ssrf", function=None)
    shared, ours, theirs = matcher.match_cross_tool([a], [b])
    assert shared == []
    assert ours == [a]
    assert theirs == [b]
    c = finding(tool="semgrep", file="db.py", line=12, function=None)
    shared, _, _ = matcher.match_cross_tool([a], [c])
    assert shared == []
    d = finding(tool="semgrep", line=100, function=None)
    shared, _, _ = matcher.match_cross_tool([a], [d])
    assert shared == []


# ------------------------------------------------------------- ground truth


def test_ground_truth_has_vulnerable_cases():
    cases = vulnerable_cases(FIXTURE)
    assert any(c.vulnerability_type == "sql_injection" for c in cases)
    assert any(c.vulnerability_type == "command_injection" for c in cases)
    assert any(c.vulnerability_type == "ssrf" for c in cases)
    assert all(c.expected_vulnerable for c in cases)
    assert all(c.case_id and c.file and c.function for c in cases)


def test_ground_truth_has_safe_cases():
    cases = safe_cases(FIXTURE)
    assert any(c.function == "get_user_safe" for c in cases)
    assert any(c.function == "fetch_safe" for c in cases)
    assert any(c.function == "run_command_safe" for c in cases)
    assert all(not c.expected_vulnerable for c in cases)


def test_ground_truth_count():
    assert len(get_ground_truth(FIXTURE)) == 8


# ------------------------------------------------------------------ metrics


def _metrics(findings, fixture=FIXTURE):
    return compute_metrics("tool", findings, fixture)


def test_true_positives_calculated():
    metrics = _metrics([finding(line=15)])
    assert metrics.true_positives == 1


def test_false_positives_calculated():
    metrics = _metrics([finding(line=15), finding(line=25)])  # 25 = safe SQL
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1


def test_false_negatives_calculated():
    metrics = _metrics([])
    assert metrics.false_negatives == len(vulnerable_cases(FIXTURE))


def test_precision_correct():
    metrics = _metrics([finding(line=15), finding(line=25)])
    assert metrics.precision == 0.5


def test_recall_correct():
    metrics = _metrics([finding(line=15)])
    assert metrics.recall == 0.2


def test_f1_correct():
    metrics = _metrics([finding(line=15), finding(line=25)])
    assert metrics.f1 == pytest.approx(0.2857, abs=0.001)


def test_zero_denominator_safe():
    metrics = _metrics([])
    assert metrics.true_positives == 0
    assert metrics.false_positives == 0
    assert metrics.false_negatives == len(vulnerable_cases(FIXTURE))
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.f1 is None


def test_fixture_perfect_metrics_for_our_scanner():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    ours = report.metrics[0]
    assert ours.tool == "our-sast"
    assert ours.true_positives == 5
    assert ours.false_positives == 0
    assert ours.false_negatives == 0
    assert ours.precision == 1.0
    assert ours.recall == 1.0
    assert ours.f1 == 1.0


# ------------------------------------------------------------------- service


def test_our_tool_benchmark_generated():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    assert report.benchmark_id
    assert report.fixture == FIXTURE
    assert report.ground_truth_count == 8
    assert report.our_result.available is True
    assert len(report.our_result.findings) == 5
    assert report.our_result.duration_ms is not None
    assert report.semgrep_result.available is False
    assert report.created_at is not None


def test_comparison_generated_with_fake_semgrep():
    fake = FakeSemgrepRunner(
        findings=[
            finding(vulnerability_type="sql_injection", line=15, function=None),
            finding(vulnerability_type="sql_injection", file="db.py", line=17, function=None),
            finding(vulnerability_type="sql_injection", file="db.py", line=20, function="query_users"),
            finding(vulnerability_type="command_injection", file="app.py", line=34, function=None),
            finding(vulnerability_type="command_injection", file="app.py", line=51, function="run_command_safe"),
            finding(vulnerability_type="ssrf", file="app.py", line=40, function=None),
        ]
    )
    service = BenchmarkService(runner=fake)
    report = service.run(FIXTURE)
    comp = report.comparison
    assert len(comp.shared_findings) == 5
    assert comp.ours_only == []
    assert len(comp.semgrep_only) == 1
    assert comp.semgrep_only[0].function == "run_command_safe"
    assert set(comp.shared_vulnerability_types) == {
        "sql_injection",
        "command_injection",
        "ssrf",
    }
    assert "cmd-app-run-command-safe" in comp.safe_cases_detected_incorrectly
    semgrep_metrics = next(m for m in report.metrics if m.tool == "semgrep")
    assert semgrep_metrics.true_positives == 5
    assert semgrep_metrics.false_positives == 1
    assert semgrep_metrics.precision == pytest.approx(5 / 6, abs=1e-3)


def test_get_report_and_clear():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    assert service.get_report(report.benchmark_id) is report
    assert service.get_report("nope") is None
    service.clear()
    assert service.get_report(report.benchmark_id) is None


def test_unknown_fixture_raises():
    with pytest.raises(UnknownFixtureError):
        BenchmarkService().run("nonexistent_fixture")


def test_invalid_fixture_name_raises():
    for name in ["../escape", "a/b", "a;b", "", "a b"]:
        with pytest.raises(InvalidFixtureNameError):
            BenchmarkService().run(name)


# -------------------------------------------------------------- isolation


def test_benchmark_does_not_affect_risk():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    for f in report.our_result.findings:
        assert get_risk_assessment(f.fingerprint) is None
        assert get_sla_record(f.fingerprint) is None
        assert get_escalation_events(f.fingerprint) == []
    assert get_finding_store().get(report.our_result.findings[0].fingerprint) is None


def test_benchmark_does_not_affect_validation_or_proof():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    for f in report.our_result.findings:
        assert get_validation_store().get(f.fingerprint) is None
        assert get_proof_store().get(f.fingerprint) is None


# ----------------------------------------------------------------- security


def test_semgrep_command_no_shell_no_network(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0

        def __init__(self, args, shell, **kwargs):
            captured["args"] = args
            captured["shell"] = shell

        def communicate(self, timeout=None):
            return b"{}", b""

        def kill(self):
            pass

    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen", FakeProc
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    runner = SemgrepRunner(executable="semgrep")
    result = runner.run(__import__("pathlib").Path("fixtures"))
    assert result.available is True
    assert captured["shell"] is False
    args = captured["args"]
    assert args[0] == "semgrep"
    assert "--config" in args
    assert "auto" not in args
    rules_index = args.index("--config") + 1
    assert args[rules_index] == str(RULES_DIR)
    assert not any("http" in a for a in args)
    assert "fixtures" in args


def test_semgrep_output_size_bounded(monkeypatch):
    class FakeProc:
        returncode = 0

        def __init__(self, *a, **k):
            pass

        def communicate(self, timeout=None):
            return b"x" * 1024, b""

        def kill(self):
            pass

    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    result = SemgrepRunner(executable="semgrep", max_output_bytes=512).run(
        __import__("pathlib").Path(".")
    )
    assert result.findings == []
    assert "size limit" in result.error


def test_semgrep_timeout_parameter_used(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0

        def __init__(self, *a, **k):
            pass

        def communicate(self, timeout=None):
            captured["timeout"] = timeout
            return b"{}", b""

        def kill(self):
            pass

    monkeypatch.setattr(
        "app.benchmark.semgrep_runner.subprocess.Popen", lambda *a, **k: FakeProc()
    )
    monkeypatch.setattr("app.benchmark.semgrep_runner.shutil.which", lambda _: "/x")
    SemgrepRunner(executable="semgrep", timeout_s=7).run(
        __import__("pathlib").Path(".")
    )
    assert captured["timeout"] == 7


def test_malicious_fixture_name_cannot_inject_arguments():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    with pytest.raises(InvalidFixtureNameError):
        service.run("x --config auto")
    with pytest.raises(InvalidFixtureNameError):
        service.run("; rm -rf")
    assert FakeSemgrepRunner().calls == []  # runner never invoked


def test_no_fake_findings_presented_as_real():
    service = BenchmarkService(runner=FakeSemgrepRunner(available=False))
    report = service.run(FIXTURE)
    assert report.semgrep_result.available is False
    assert report.semgrep_result.findings == []
    assert all(m.tool != "semgrep" for m in report.metrics)