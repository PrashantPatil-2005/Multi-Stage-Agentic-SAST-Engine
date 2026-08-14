"""VALIDATE stage API endpoint tests (FakeLLMProvider only)."""

import pytest
from fastapi.testclient import TestClient

from app.api.routes.validations import get_validation_service
from app.scan.service import ScanService
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files


def test_validation_routes_registered(client):
    """The VALIDATE endpoints must exist in the route table (OpenAPI paths)."""
    paths = client.app.openapi()["paths"]
    assert "/api/findings/{finding_id}/validate" in paths
    assert "post" in paths["/api/findings/{finding_id}/validate"]
    assert "/api/findings/{finding_id}/validation" in paths
    assert "get" in paths["/api/findings/{finding_id}/validation"]


@pytest.fixture
def registered_report():
    get_finding_store().clear()
    get_validation_store().clear()
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    return report


@pytest.fixture
def fake_app(client, registered_report):
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
    )
    yield client
    app.dependency_overrides.clear()


def test_post_validate_returns_validation_result(fake_app, registered_report):
    finding = next(f for f in registered_report.findings if f.vulnerability_type == "sql_injection")
    response = fake_app.post(f"/api/findings/{finding.id}/validate", json={"provider": "openai_compatible"})
    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == finding.id
    assert body["verdict"] == "true_positive"
    assert body["confidence"] == 0.91
    assert body["recommended_next_step"] == "prove"
    assert body["model"] == "fake-model"
    assert body["evidence"]["finding_id"] == finding.id


def test_get_validation_returns_recorded_result(fake_app, registered_report):
    finding = next(f for f in registered_report.findings if f.vulnerability_type == "command_injection")
    fake_app.post(f"/api/findings/{finding.id}/validate", json={"provider": "openai_compatible"})
    response = fake_app.get(f"/api/findings/{finding.id}/validation")
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "true_positive"
    assert body["finding_id"] == finding.id


def test_validate_unknown_finding_404(fake_app):
    response = fake_app.post("/api/findings/does-not-exist/validate", json={"provider": "openai_compatible"})
    assert response.status_code == 404


def test_get_validation_for_unvalidated_finding_404(fake_app, registered_report):
    finding = next(f for f in registered_report.findings if f.vulnerability_type == "ssrf")
    response = fake_app.get(f"/api/findings/{finding.id}/validation")
    assert response.status_code == 404


def test_validate_without_llm_configuration_returns_503(client, registered_report, monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService()
    try:
        finding = next(
            f for f in registered_report.findings if f.vulnerability_type == "sql_injection"
        )
        response = client.post(
            f"/api/findings/{finding.id}/validate", json={"provider": "openai_compatible"}
        )
        assert response.status_code == 503
        assert "not configured" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()
