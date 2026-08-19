"""Tests for the ProofPlanner: plan generation, supported types, and
harness scripts for deserialization and unsupported vulnerability types."""

import pytest

from app.prove.planner import (
    APPROVED_HARNESSES,
    HARNESS_SCRIPTS,
    SUPPORTED_PROOF_TYPES,
    ProofPlanner,
)
from app.scan.models import CandidateFinding, SinkRef, SourceRef, TaintStep, Evidence


def _make_finding(vuln_type: str) -> CandidateFinding:
    return CandidateFinding(
        id=f"test-{vuln_type}-001",
        vulnerability_type=vuln_type,
        severity="high",
        confidence=0.9,
        source=SourceRef(file="app.py", line=10, snippet="request.args.get('x')", kind="request_param"),
        sink=SinkRef(file="app.py", line=20, snippet="sink_call(x)", kind="generic"),
        taint_path=[
            TaintStep(file="app.py", line=10, snippet="request.args.get('x')", step_type="source"),
            TaintStep(file="app.py", line=20, snippet="sink_call(x)", step_type="sink"),
        ],
        evidence=Evidence(
            source_snippet="request.args.get('x')",
            sink_snippet="sink_call(x)",
            taint_path=[],
            relevant_lines=[10, 20],
            sanitizer_observations=[],
        ),
    )


class TestSupportedTypes:
    def test_supported_types_list(self):
        assert "sql_injection" in SUPPORTED_PROOF_TYPES
        assert "command_injection" in SUPPORTED_PROOF_TYPES
        assert "ssrf" in SUPPORTED_PROOF_TYPES
        assert "deserialization" in SUPPORTED_PROOF_TYPES

    def test_is_supported(self):
        planner = ProofPlanner()
        assert planner.is_supported("sql_injection") is True
        assert planner.is_supported("deserialization") is True
        assert planner.is_supported("xss") is False
        assert planner.is_supported("path_traversal") is False


class TestUnsupportedReasons:
    def test_xss_unsupported_reason(self):
        planner = ProofPlanner()
        reason = planner.unsupported_reason("xss")
        assert reason is not None
        assert "browser" in reason.lower()

    def test_path_traversal_unsupported_reason(self):
        planner = ProofPlanner()
        reason = planner.unsupported_reason("path_traversal")
        assert reason is not None
        assert "file system" in reason.lower()

    def test_idor_unsupported_reason(self):
        planner = ProofPlanner()
        reason = planner.unsupported_reason("idor")
        assert reason is not None
        assert "authentication" in reason.lower()

    def test_unknown_type_unsupported_reason(self):
        planner = ProofPlanner()
        reason = planner.unsupported_reason("unknown_vuln_type")
        assert reason is not None
        assert "No automated proof harness" in reason

    def test_supported_type_returns_none(self):
        planner = ProofPlanner()
        assert planner.unsupported_reason("sql_injection") is None
        assert planner.unsupported_reason("deserialization") is None


class TestDeserializationPlan:
    def test_deser_plan_exists(self):
        planner = ProofPlanner()
        finding = _make_finding("deserialization")
        plan = planner.plan(finding)
        assert plan is not None
        assert plan.vulnerability_type == "deserialization"
        assert plan.harness == "deserialization_proof"

    def test_deser_plan_has_marker(self):
        planner = ProofPlanner()
        finding = _make_finding("deserialization")
        plan = planner.plan(finding)
        assert "PROVE_DESER_MARKER" in plan.input_value

    def test_deser_plan_policy(self):
        planner = ProofPlanner()
        finding = _make_finding("deserialization")
        plan = planner.plan(finding)
        assert plan.policy.network_enabled is False
        assert plan.policy.allow_loopback is False


class TestHarnessScripts:
    def test_all_approved_harnesses_have_scripts(self):
        for name in APPROVED_HARNESSES:
            assert name in HARNESS_SCRIPTS, f"Missing harness script for {name}"

    def test_all_harness_scripts_are_strings(self):
        for name, fn in HARNESS_SCRIPTS.items():
            script = fn()
            assert isinstance(script, str), f"Harness {name} script is not a string"
            assert len(script) > 0, f"Harness {name} script is empty"

    def test_deser_harness_has_sandbox_guard(self):
        script = HARNESS_SCRIPTS["deserialization_proof"]()
        assert "SANDBOX_DIR" in script
        assert "assert" in script

    def test_deser_harness_imports_pickle(self):
        script = HARNESS_SCRIPTS["deserialization_proof"]()
        assert "pickle" in script

    def test_deser_harness_imports_json(self):
        script = HARNESS_SCRIPTS["deserialization_proof"]()
        assert "json" in script

    def test_probe_harness_is_test_only(self):
        script = HARNESS_SCRIPTS["probe_proof"]()
        assert "PROBE_ACTION" in script
