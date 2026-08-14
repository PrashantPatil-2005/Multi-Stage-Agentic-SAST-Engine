"""VALIDATE stage unit tests (no real LLM is ever called)."""

import json
import os

import pytest

from app.scan.service import ScanService
from app.validate.evidence import EvidenceBuilder
from app.validate.models import ValidationRequest
from app.validate.providers import get_provider
from app.validate.providers.base import ConfigurationError
from app.validate.service import ValidationService
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import VULN_APP, scan_fixture_files, scan_sources

FIXTURE_SOURCES = {name: (VULN_APP / name).read_text(encoding="utf-8") for name in ("app.py", "db.py")}


def _report(*names: str):
    return scan_fixture_files(*names)


def _finding(report, vuln: str):
    return next(f for f in report.findings if f.vulnerability_type == vuln)


def _findings(report, vuln: str):
    return [f for f in report.findings if f.vulnerability_type == vuln]


# ------------------------------------------------------------ verdict mapping

def test_true_positive_sql_injection():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    provider = FakeLLMProvider(verdict="true_positive", confidence=0.94, next_step="prove")
    result = ValidationService(provider=provider).validate(finding, sources=FIXTURE_SOURCES)

    assert result.finding_id == finding.id
    assert result.verdict == "true_positive"
    assert result.confidence == 0.94
    assert result.recommended_next_step == "prove"
    assert result.model == "fake-model"
    assert result.validated_at is not None
    assert result.evidence is not None
    assert result.metadata is not None
    assert result.metadata.evidence_hash


def test_false_positive_sql_injection():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    provider = FakeLLMProvider(
        verdict="false_positive",
        confidence=0.85,
        reasoning="sanitizer observed in surrounding context",
        next_step="discard",
    )
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "false_positive"
    assert result.recommended_next_step == "discard"


def test_uncertain_finding():
    report = _report("app.py")
    finding = _finding(report, "command_injection")
    provider = FakeLLMProvider(
        verdict="uncertain",
        confidence=0.5,
        reasoning="sanitizer presence cannot be established from evidence",
        next_step="manual_review",
    )
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "uncertain"
    assert result.recommended_next_step == "manual_review"


# ------------------------------------------------------------ per vuln type

def test_command_injection_validation():
    report = _report("app.py")
    finding = _finding(report, "command_injection")
    result = ValidationService(provider=FakeLLMProvider()).validate(finding)
    assert result.evidence.vulnerability_type == "command_injection"
    assert result.evidence.sink_snippet == "subprocess.run(cmd, shell=True)"
    assert result.evidence.source_line == 33


def test_ssrf_validation():
    report = _report("app.py")
    finding = _finding(report, "ssrf")
    result = ValidationService(provider=FakeLLMProvider()).validate(finding)
    assert result.evidence.vulnerability_type == "ssrf"
    assert result.evidence.sink_snippet == "requests.get(url, timeout=5)"


# ------------------------------------------------------------ evidence package

def test_evidence_contains_correct_source():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    evidence = EvidenceBuilder(FIXTURE_SOURCES).build(finding)
    assert evidence.source_file == "app.py"
    assert evidence.source_line == 12
    assert evidence.source_snippet == "def get_user(user_id: str) -> dict:"


def test_evidence_contains_correct_sink():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    evidence = EvidenceBuilder(FIXTURE_SOURCES).build(finding)
    assert evidence.sink_file == "app.py"
    assert evidence.sink_line == 15
    assert evidence.sink_snippet.startswith("conn.execute(query)")


def test_evidence_contains_taint_path():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    evidence = EvidenceBuilder(FIXTURE_SOURCES).build(finding)
    assert [s.step_type for s in evidence.taint_path] == [
        "source",
        "string_construction",
        "sink",
    ]
    assert evidence.relevant_lines == [12, 14, 15]


def test_repository_outside_context_not_included():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    evidence = EvidenceBuilder(FIXTURE_SOURCES).build(finding)
    assert set(evidence.surrounding_context) == {"app.py"}
    context_text = "\n".join(evidence.surrounding_context["app.py"])
    assert "fetch_safe" not in context_text  # far away from the finding
    assert "get_user_safe" not in context_text  # outside the context window
    assert "def get_user" in context_text  # the finding itself is present
    # db.py was available but irrelevant -> never sent
    assert "db.py" not in evidence.surrounding_context


def test_scanner_confidence_separate_from_llm_confidence():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    assert finding.confidence == 0.7  # scanner confidence
    provider = FakeLLMProvider(confidence=0.94)
    result = ValidationService(provider=provider).validate(finding)
    assert result.evidence.scanner_confidence == 0.7
    assert result.confidence == 0.94
    assert result.confidence != result.evidence.scanner_confidence


# ------------------------------------------------------------ malformed output

def test_invalid_confidence_rejected():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    bad = json.dumps(
        {
            "verdict": "true_positive",
            "confidence": 1.7,  # out of [0, 1]
            "reasoning": "x",
            "evidence_used": [],
            "missing_evidence": [],
            "recommended_next_step": "prove",
        }
    )
    provider = FakeLLMProvider(script=[bad, bad])
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "uncertain"
    assert result.confidence == 0.0
    assert result.recommended_next_step == "manual_review"


def test_invalid_verdict_rejected():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    bad = json.dumps(
        {
            "verdict": "definitely_vulnerable",  # not a valid verdict
            "confidence": 0.9,
            "reasoning": "x",
            "evidence_used": [],
            "missing_evidence": [],
            "recommended_next_step": "prove",
        }
    )
    provider = FakeLLMProvider(script=[bad, bad])
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "uncertain"


def test_malformed_json_causes_repair_attempt():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    good = json.dumps(
        {
            "verdict": "true_positive",
            "confidence": 0.9,
            "reasoning": "repaired response",
            "evidence_used": ["taint_path"],
            "missing_evidence": [],
            "recommended_next_step": "prove",
        }
    )
    provider = FakeLLMProvider(script=["this is not json", good])
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "true_positive"
    assert result.reasoning == "repaired response"
    assert result.metadata.retry_count == 1
    assert "not valid JSON" in provider.prompts[1]


def test_second_malformed_response_results_in_uncertain():
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    provider = FakeLLMProvider(script=["not json", "still not json"])
    result = ValidationService(provider=provider).validate(finding)
    assert result.verdict == "uncertain"
    assert result.confidence == 0.0
    assert result.metadata.retry_count == 1
    assert "malformed" in result.reasoning.lower()


# ------------------------------------------------------------ configuration

def test_missing_llm_configuration_handled_gracefully(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    with pytest.raises(ConfigurationError, match="not configured"):
        get_provider()
    report = _report("app.py")
    finding = _finding(report, "sql_injection")
    with pytest.raises(ConfigurationError, match="not configured"):
        ValidationService().validate(finding)


def test_unknown_provider_rejected():
    with pytest.raises(ConfigurationError, match="unknown LLM provider"):
        get_provider("definitely_not_a_provider")


def test_provider_configuration_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    from app.validate.providers.openai_compatible import OpenAICompatibleProvider

    provider = get_provider()
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == "validator-1"


# ------------------------------------------------------------ batch

def test_batch_validation_preserves_finding_ids():
    report = _report("app.py", "db.py")
    provider = FakeLLMProvider()
    results = ValidationService(provider=provider).validate_report(report, sources=FIXTURE_SOURCES)
    assert len(results) == len(report.findings) == 5
    assert [r.finding_id for r in results] == [f.id for f in report.findings]
    assert all(r.verdict == "true_positive" for r in results)
    # each result carries exactly its own evidence package
    assert [r.evidence.finding_id for r in results] == [f.id for f in report.findings]


def test_evidence_never_leaks_between_findings():
    report = _report("app.py", "db.py")
    provider = FakeLLMProvider()
    results = ValidationService(provider=provider).validate_report(report, sources=FIXTURE_SOURCES)
    assert {r.finding_id for r in results} == {f.id for f in report.findings}
    # Core fields of each package must never contain another finding's
    # source/sink snippets. (surrounding_context legitimately shares
    # adjacent lines, so it is excluded from this check.)
    for result in results:
        ev = result.evidence
        core = json.dumps(
            {
                "source_snippet": ev.source_snippet,
                "sink_snippet": ev.sink_snippet,
                "taint_path": [s.model_dump() for s in ev.taint_path],
                "relevant_lines": ev.relevant_lines,
                "sanitizer_observations": ev.sanitizer_observations,
            }
        )
        for other in results:
            if other.finding_id == result.finding_id:
                continue
            assert other.evidence.sink_snippet not in core
            assert other.evidence.source_snippet not in core


# ------------------------------------------------------------ redaction

def test_secret_redaction_applied_to_evidence():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    password = 'hunter2-super-secret'\n"
                "    requests.get(url)\n"
            )
        }
    )
    finding = report.findings[0]
    sources = {
        "app.py": (
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    password = 'hunter2-super-secret'\n"
            "    requests.get(url)\n"
        )
    }
    evidence = EvidenceBuilder(sources).build(finding)
    payload = json.dumps(evidence.model_dump(mode="json"))
    assert "hunter2-super-secret" not in payload
    assert "<REDACTED:secret>" in payload


def test_validation_request_shape():
    report = _report("app.py")
    finding = _finding(report, "ssrf")
    evidence = EvidenceBuilder(FIXTURE_SOURCES).build(finding)
    request = ValidationRequest(finding_id=finding.id, evidence=evidence, provider="fake")
    assert request.finding_id == finding.id
    assert request.evidence.finding_id == finding.id