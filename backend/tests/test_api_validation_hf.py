"""VALIDATE API tests against the real HuggingFaceLLMProvider (mocked HTTP).

Proves the existing POST /api/findings/{finding_id}/validate endpoint works
with the production provider while keeping tests deterministic and offline.
"""

import json

import httpx
import pytest
from httpx import MockTransport, Response

from app.api.routes.validations import get_validation_service
from app.scan.service import ScanService
from app.validate.providers.huggingface import HuggingFaceLLMProvider
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.scan_test_helpers import scan_fixture_files

TOKEN = "hf-api-test-token-never-real"

VERDICT_JSON = json.dumps(
    {
        "verdict": "true_positive",
        "confidence": 0.9,
        "reasoning": "attacker input reaches the sink via the taint path",
        "evidence_used": ["source_snippet", "taint_path", "sink_snippet"],
        "missing_evidence": [],
        "recommended_next_step": "prove",
    }
)


def chat_response(content: str) -> Response:
    return Response(
        200,
        json={
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": content}}],
        },
    )


@pytest.fixture
def registered_report():
    get_finding_store().clear()
    get_validation_store().clear()
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    return report


def hf_app(client, handler) -> None:
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=HuggingFaceLLMProvider(
            base_url="https://router.huggingface.co/v1",
            api_key=TOKEN,
            model="hf-test-model",
            transport=MockTransport(handler),
        )
    )


def test_post_validate_creates_validation_result(client, registered_report):
    hf_app(client, lambda request: chat_response(VERDICT_JSON))
    finding = next(
        f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
    )
    response = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == finding.id
    assert body["verdict"] == "true_positive"
    assert body["confidence"] == 0.9
    assert body["reasoning"] == "attacker input reaches the sink via the taint path"
    assert body["evidence_used"] == ["source_snippet", "taint_path", "sink_snippet"]
    assert body["recommended_next_step"] == "prove"
    assert body["model"] == "hf-test-model"
    assert body["validated_at"] is not None
    assert body["metadata"]["provider"] == "huggingface"
    assert body["metadata"]["model"] == "hf-test-model"


def test_repeated_validation_follows_existing_semantics(client, registered_report):
    responses = iter(
        [
            chat_response(VERDICT_JSON),
            chat_response(
                json.dumps(
                    {
                        "verdict": "uncertain",
                        "confidence": 0.4,
                        "reasoning": "second opinion: insufficient evidence",
                        "evidence_used": ["taint_path"],
                        "missing_evidence": ["sanitizer check"],
                        "recommended_next_step": "manual_review",
                    }
                )
            ),
        ]
    )

    def handler(request: httpx.Request) -> Response:
        return next(responses)

    hf_app(client, handler)
    finding = next(
        f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
    )
    first = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert first.status_code == 200
    assert first.json()["verdict"] == "true_positive"
    second = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert second.status_code == 200
    assert second.json()["verdict"] == "uncertain"
    stored = client.get(f"/api/findings/{finding.id}/validation")
    assert stored.status_code == 200
    assert stored.json()["verdict"] == "uncertain"
    assert stored.json()["confidence"] == 0.4
    assert stored.json()["missing_evidence"] == ["sanitizer check"]


def test_provider_unavailable_returns_safe_503(client, registered_report):
    def handler(request: httpx.Request) -> Response:
        raise httpx.ConnectError("no route to host")

    hf_app(client, handler)
    finding = next(
        f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
    )
    response = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "LLM validation is currently unavailable" in detail
    assert "no route to host" not in detail


def test_provider_5xx_returns_safe_503(client, registered_report):
    def handler(request: httpx.Request) -> Response:
        raise httpx.ConnectError("boom")

    hf_app(client, handler)
    finding = next(
        f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
    )
    response = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert response.status_code == 503
    assert "boom" not in response.json()["detail"]


def test_api_key_never_appears_in_responses(client, registered_report):
    hf_app(client, lambda request: chat_response(VERDICT_JSON))
    finding = next(
        f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
    )
    response = client.post(f"/api/findings/{finding.id}/validate", json={})
    assert TOKEN not in response.text
    stored = client.get(f"/api/findings/{finding.id}/validation")
    assert TOKEN not in stored.text
