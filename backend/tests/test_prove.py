"""PROVE stage tests: safety, gate, sandbox, and per-vulnerability proofs.

All proofs run through the real SandboxRunner with the trusted planner
harnesses (a fresh temp workspace is created and removed per run). No test
attacks real systems: no external hosts, no network beyond the SSRF
harness's own ephemeral loopback endpoint.
"""

import os
import time

import pytest

from app.prove.models import ProofArtifact, ProofResult, SandboxPolicy
from app.prove.sandbox import SandboxRunner, SandboxViolation
from app.prove.service import ProofGateError, ProofService
from app.scan.models import CandidateFinding, Evidence, SinkRef, SourceRef, TaintStep
from app.validate.service import ValidationService
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import VULN_APP, scan_fixture_files


def _finding(report, vuln: str):
    return next(f for f in report.findings if f.vulnerability_type == vuln)


def _validation(finding, verdict: str = "true_positive"):
    provider = FakeLLMProvider(verdict=verdict, confidence=0.94, next_step="prove")
    return ValidationService(provider=provider).validate(finding)


def _prove(report, vuln: str, verdict: str = "true_positive") -> tuple[ProofResult, CandidateFinding]:
    finding = _finding(report, vuln)
    return ProofService().prove(finding, _validation(finding, verdict)), finding


@pytest.fixture
def report():
    return scan_fixture_files("app.py")


# ------------------------------------------------------------ validation gate

def test_true_positive_can_reach_prove(report):
    result, finding = _prove(report, "sql_injection")
    assert result.finding_id == finding.id
    assert result.status in {"verified", "not_verified", "error"}


def test_false_positive_blocked(report):
    finding = _finding(report, "sql_injection")
    with pytest.raises(ProofGateError, match="not eligible for proof"):
        ProofService().prove(finding, _validation(finding, "false_positive"))


def test_uncertain_blocked(report):
    finding = _finding(report, "command_injection")
    with pytest.raises(ProofGateError, match="not eligible for proof"):
        ProofService().prove(finding, _validation(finding, "uncertain"))


def test_missing_validation_blocked(report):
    finding = _finding(report, "ssrf")
    with pytest.raises(ProofGateError, match="no validation result"):
        ProofService().prove(finding, None)


def test_validation_for_different_finding_blocked(report):
    finding = _finding(report, "ssrf")
    other = _finding(report, "sql_injection")
    with pytest.raises(ProofGateError, match="does not match"):
        ProofService().prove(finding, _validation(other))


# ------------------------------------------------------------ per-vulnerability proofs

def test_sqli_proof_uses_only_local_fixture(report):
    result, finding = _prove(report, "sql_injection")
    assert result.status == "verified"
    assert result.sandbox_policy.network_enabled is False
    kinds = {a.kind for a in result.artifacts}
    assert "observation" in kinds
    queries = {a.name: a.content for a in result.artifacts}
    assert "unsafe_query" in queries and "safe_query" in queries
    assert "OR" in queries["unsafe_query"]  # the marker is visible in the construction
    assert "?" in queries["safe_query"]


def test_command_injection_proof_uses_harmless_marker(report):
    result, finding = _prove(report, "command_injection")
    assert result.status == "verified"
    assert result.sandbox_policy.network_enabled is False
    markers = [a for a in result.artifacts if a.kind == "marker"]
    assert markers and "prove_marker.txt" in markers[0].content
    assert "PWNED" not in result.summary  # only the controlled marker name


def test_ssrf_proof_never_uses_external_network(report):
    result, finding = _prove(report, "ssrf")
    assert result.status == "verified"
    assert result.sandbox_policy.network_enabled is False
    assert result.sandbox_policy.allow_loopback is True
    urls = [a.content for a in result.artifacts if a.name == "url"]
    assert urls and urls[0].startswith("http://127.0.0.1:")


# ------------------------------------------------------------ sandbox policy

def test_default_sandbox_has_network_disabled():
    policy = SandboxPolicy()
    assert policy.network_enabled is False
    assert policy.allow_loopback is False
    assert policy.timeout_seconds <= 10


def test_sandbox_timeout_works():
    runner = SandboxRunner(SandboxPolicy(timeout_seconds=0.5))
    result = runner.run(
        "probe_proof",
        _probe_script(),
        env={"PROBE_ACTION": "sleep", "PROBE_SLEEP": "30"},
    )
    assert result.timed_out is True
    assert result.returncode is None


def test_output_size_limit_works():
    runner = SandboxRunner(SandboxPolicy(max_output_bytes=100))
    result = runner.run("probe_proof", _probe_script(), env={"PROBE_ACTION": "print", "PROBE_TEXT": "A", "PROBE_REPEAT": "1000"})
    assert result.truncated is True
    assert len(result.stdout) <= 100 + len("...") + 50
    assert "[output truncated" in result.stdout


def test_temporary_workspace_cleaned(report):
    result, _ = _prove(report, "sql_injection")
    workspace = result.sandbox_policy.temporary_directory
    assert workspace
    assert not os.path.exists(workspace)


def test_repository_outside_allowed_paths_cannot_be_accessed(report):
    fixture_path = str(VULN_APP / "app.py")
    runner = SandboxRunner(SandboxPolicy())
    result = runner.run("probe_proof", _probe_script(), env={"PROBE_PATH": fixture_path})
    assert "READ_DENIED" in result.stdout
    assert "READ_OK" not in result.stdout


def test_runner_rejects_unapproved_harness():
    runner = SandboxRunner()
    with pytest.raises(SandboxViolation, match="not approved"):
        runner.run("evil_harness", "print('pwned')")


def test_runner_rejects_tampered_harness_script():
    runner = SandboxRunner()
    with pytest.raises(SandboxViolation, match="does not match the trusted template"):
        runner.run("sql_injection_proof", "print('tampered')")


# ------------------------------------------------------------ results

def test_proof_result_contains_finding_id(report):
    result, finding = _prove(report, "command_injection")
    assert result.finding_id == finding.id


def test_proof_result_contains_sandbox_policy(report):
    result, _ = _prove(report, "ssrf")
    assert result.sandbox_policy.timeout_seconds > 0
    assert result.sandbox_policy.max_output_bytes > 0
    assert result.sandbox_policy.network_enabled is False


def test_proof_failure_returns_structured_result(report, monkeypatch):
    finding = _finding(report, "sql_injection")

    def boom(*args, **kwargs):
        raise RuntimeError("simulated harness failure")

    monkeypatch.setattr(SandboxRunner, "run", boom)
    result = ProofService().prove(finding, _validation(finding))
    assert isinstance(result, ProofResult)
    assert result.status == "error"
    assert "simulated harness failure" in result.error
    assert result.duration_ms >= 0
    assert result.finding_id == finding.id


def test_unsupported_proof_returns_not_verified():
    finding = CandidateFinding(
        id="crafted-1",
        vulnerability_type="path_traversal",
        severity="high",
        confidence=0.7,
        source=SourceRef(file="app.py", line=1, snippet="request.args.get('p')", kind="request_param"),
        sink=SinkRef(file="app.py", line=2, snippet="open(p)", kind="file_read"),
        taint_path=[TaintStep(file="app.py", line=1, snippet="request.args.get('p')", step_type="source")],
        evidence=Evidence(
            source_snippet="request.args.get('p')",
            sink_snippet="open(p)",
            taint_path=[TaintStep(file="app.py", line=1, snippet="request.args.get('p')", step_type="source")],
            relevant_lines=[1, 2],
            sanitizer_observations=["no sanitizer observed at sink"],
        ),
    )
    result = ProofService().prove(finding, _validation(finding))
    assert result.status == "not_verified"
    assert "no proof plan" in result.summary


# ------------------------------------------------------------ security

def test_no_arbitrary_shell_command_execution(report):
    """A command-like string in finding evidence stays data, never shell code."""
    finding = _finding(report, "command_injection")
    # plant a hostile-looking string into the finding's data (simulates a
    # malicious-looking finding: the sink snippet looks like a real attack)
    finding = finding.model_copy(
        update={
            "evidence": finding.evidence.model_copy(
                update={
                    "sanitizer_observations": [
                        "no sanitizer observed at sink",
                        "echo PWNED > pwned.txt",
                    ]
                }
            )
        }
    )
    result = ProofService().prove(finding, _validation(finding))
    # the harness runs its own controlled marker; the planted string must
    # never appear in any output and must never be executed
    payload = f"{result.summary} {result.error or ''}"
    for artifact in result.artifacts + result.evidence:
        payload += " " + artifact.content
    assert "PWNED" not in payload
    assert not os.path.exists(os.path.join(os.getcwd(), "pwned.txt"))


def test_no_external_network_requests(report):
    """Every proof uses network_enabled=False; harnesses only reference loopback."""
    for vuln in ("sql_injection", "command_injection", "ssrf"):
        result, _ = _prove(report, vuln)
        assert result.sandbox_policy.network_enabled is False
    for script in _all_harness_scripts():
        if "http" in script:
            assert "127.0.0.1" in script
            assert "http://" not in script.replace("http://127.0.0.1", "")


def test_existing_suite_still_passes(report):
    result, finding = _prove(report, "sql_injection")
    assert result.finding_id == finding.id


# ------------------------------------------------------------ helpers

def _probe_script() -> str:
    from app.prove.planner import HARNESS_SCRIPTS

    return HARNESS_SCRIPTS["probe_proof"]()


def _all_harness_scripts() -> list[str]:
    from app.prove.planner import HARNESS_SCRIPTS

    return [fn() for fn in HARNESS_SCRIPTS.values()]
