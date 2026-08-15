"""HuggingFaceLLMProvider tests - mocked HTTP only, never a real API call.

Covers provider behavior (§15) and the full service chain
CandidateFinding -> ValidationService -> HuggingFaceLLMProvider ->
ValidationResult (§16).
"""

import json

import httpx
import pytest
from httpx import MockTransport, Response

from app.validate.providers.base import ConfigurationError
from app.validate.providers.huggingface import DEFAULT_BASE_URL, HuggingFaceLLMProvider
from app.validate.service import ValidationService
from tests.scan_test_helpers import VULN_APP, scan_fixture_files

FIXTURE_SOURCES = {name: (VULN_APP / name).read_text(encoding="utf-8") for name in ("app.py", "db.py")}

TOKEN = "hf-smoke-token-never-real"


def chat_response(content: str) -> Response:
    return Response(
        200,
        json={
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": content}}],
        },
    )


def content_payload(verdict="true_positive", confidence=0.94, reasoning="taint reaches sink",
                    evidence_used=None, missing_evidence=None, next_step="prove") -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": reasoning,
            "evidence_used": evidence_used or ["taint_path", "sink_snippet"],
            "missing_evidence": missing_evidence or [],
            "recommended_next_step": next_step,
        }
    )


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)


def make_provider(handler) -> HuggingFaceLLMProvider:
    return HuggingFaceLLMProvider(
        base_url="https://router.huggingface.co/v1",
        api_key=TOKEN,
        model="test-model",
        transport=MockTransport(handler),
    )


def make_finding():
    report = scan_fixture_files("app.py")
    return next(f for f in report.findings if f.vulnerability_type == "sql_injection")


def test_successful_hugging_face_response():
    provider = make_provider(lambda request: chat_response(content_payload()))
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "true_positive"
    assert result.confidence == 0.94
    assert result.reasoning == "taint reaches sink"
    assert result.evidence_used == ["taint_path", "sink_snippet"]
    assert result.model == "test-model"
    assert result.metadata is not None
    assert result.metadata.provider == "huggingface"
    assert result.metadata.model == "test-model"
    assert result.validated_at is not None


def test_authorization_header_and_payload(monkeypatch):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> Response:
        captured.append(request)
        return chat_response(content_payload())

    provider = make_provider(handler)
    ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert len(captured) == 1
    assert captured[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert str(captured[0].url) == "https://router.huggingface.co/v1/chat/completions"
    body = json.loads(captured[0].content)
    assert body["model"] == "test-model"
    assert body["response_format"] == {"type": "json_object"}


def test_default_base_url_used_when_unset():
    provider = HuggingFaceLLMProvider(api_key=TOKEN, model="m")
    assert provider._base_url == DEFAULT_BASE_URL


def test_timeout_produces_safe_configuration_error():
    def handler(request: httpx.Request) -> Response:
        raise httpx.ReadTimeout("slow model")

    provider = HuggingFaceLLMProvider(
        base_url="https://router.huggingface.co/v1",
        api_key=TOKEN,
        model="m",
        transport=MockTransport(handler),
    )
    with pytest.raises(ConfigurationError, match="timed out"):
        provider._complete("prompt")


def test_401_produces_safe_configuration_error():
    provider = make_provider(lambda request: Response(401, text="unauthorized"))
    with pytest.raises(ConfigurationError, match="unavailable"):
        provider._complete("prompt")


def test_403_produces_safe_configuration_error():
    provider = make_provider(lambda request: Response(403, text="forbidden"))
    with pytest.raises(ConfigurationError, match="unavailable"):
        provider._complete("prompt")


def test_429_produces_safe_configuration_error():
    provider = make_provider(lambda request: Response(429, text="rate limited"))
    with pytest.raises(ConfigurationError, match="rate limited"):
        provider._complete("prompt")


def test_500_produces_safe_configuration_error():
    provider = make_provider(lambda request: Response(500, text="boom"))
    with pytest.raises(ConfigurationError, match="provider error"):
        provider._complete("prompt")


def test_network_failure_produces_safe_configuration_error():
    def handler(request: httpx.Request) -> Response:
        raise httpx.ConnectError("no route to host")

    provider = make_provider(handler)
    with pytest.raises(ConfigurationError, match="network error"):
        provider._complete("prompt")


def test_malformed_response_body_produces_safe_configuration_error():
    provider = make_provider(lambda request: Response(200, content=b"<html>not json"))
    with pytest.raises(ConfigurationError, match="malformed"):
        provider._complete("prompt")


def test_error_messages_never_contain_the_token():
    def handler(request: httpx.Request) -> Response:
        raise httpx.ReadTimeout("slow")

    provider = make_provider(handler)
    with pytest.raises(ConfigurationError) as excinfo:
        provider._complete("prompt")
    assert TOKEN not in str(excinfo.value)


def test_invalid_verdict_falls_back_to_uncertain():
    provider = make_provider(
        lambda request: chat_response(content_payload(verdict="definitely_vulnerable"))
    )
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "uncertain"
    assert result.confidence == 0.0
    assert result.recommended_next_step == "manual_review"


def test_invalid_confidence_falls_back_to_uncertain():
    provider = make_provider(
        lambda request: chat_response(content_payload(confidence=2.5))
    )
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "uncertain"
    assert result.confidence == 0.0


def test_missing_required_field_falls_back_to_uncertain():
    missing_reasoning = json.dumps(
        {
            "verdict": "true_positive",
            "confidence": 0.9,
            "evidence_used": ["taint_path"],
            "missing_evidence": [],
            "recommended_next_step": "prove",
        }
    )
    provider = make_provider(lambda request: chat_response(missing_reasoning))
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "uncertain"
    assert "malformed" in result.reasoning.lower()


def test_false_positive_chain():
    provider = make_provider(
        lambda request: chat_response(
            content_payload(verdict="false_positive", confidence=0.85, next_step="discard")
        )
    )
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "false_positive"
    assert result.confidence == 0.85
    assert result.recommended_next_step == "discard"


def test_uncertain_chain():
    provider = make_provider(
        lambda request: chat_response(
            content_payload(
                verdict="uncertain",
                confidence=0.5,
                reasoning="sanitizer presence unknown",
                next_step="manual_review",
            )
        )
    )
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.verdict == "uncertain"
    assert result.confidence == 0.5
    assert result.recommended_next_step == "manual_review"
    assert result.reasoning == "sanitizer presence unknown"


def test_evidence_used_and_missing_evidence_stored():
    provider = make_provider(
        lambda request: chat_response(
            content_payload(
                evidence_used=["source_snippet", "taint_path", "sink_snippet"],
                missing_evidence=["runtime sanitizer proof"],
            )
        )
    )
    result = ValidationService(provider=provider).validate(make_finding(), sources=FIXTURE_SOURCES)
    assert result.evidence_used == ["source_snippet", "taint_path", "sink_snippet"]
    assert result.missing_evidence == ["runtime sanitizer proof"]
