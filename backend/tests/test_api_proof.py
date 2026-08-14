"""PROVE stage API endpoint tests (FakeLLMProvider, real sandbox harnesses)."""

import pytest

from app.api.routes.validations import get_validation_service
from app.prove.store import get_proof_store
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()


def _register_true_positive(client, report, verdict="true_positive"):
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.94)
    )
    for finding in report.findings:
        response = client.post(
            f"/api/findings/{finding.id}/validate",
            json={"provider": "openai_compatible"},
        )
        assert response.status_code == 200
    app.dependency_overrides.clear()


def test_prove_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "/api/findings/{finding_id}/prove" in paths
    assert "post" in paths["/api/findings/{finding_id}/prove"]
    assert "/api/findings/{finding_id}/proof" in paths
    assert "get" in paths["/api/findings/{finding_id}/proof"]


def test_prove_true_positive_returns_proof_result(client):
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    _register_true_positive(client, report)
    finding = next(f for f in report.findings if f.vulnerability_type == "sql_injection")
    response = client.post(f"/api/findings/{finding.id}/prove")
    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == finding.id
    assert body["vulnerability_type"] == "sql_injection"
    assert body["status"] == "verified"
    assert body["sandbox_policy"]["network_enabled"] is False
    # stored result is retrievable
    stored = client.get(f"/api/findings/{finding.id}/proof")
    assert stored.status_code == 200
    assert stored.json()["finding_id"] == finding.id


def test_prove_missing_validation_returns_404(client):
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    finding = next(f for f in report.findings if f.vulnerability_type == "ssrf")
    response = client.post(f"/api/findings/{finding.id}/prove")
    assert response.status_code == 404
    assert "validation result missing" in response.json()["detail"]


def test_prove_false_positive_returns_409(client):
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    _register_true_positive(client, report, verdict="false_positive")
    finding = next(f for f in report.findings if f.vulnerability_type == "command_injection")
    response = client.post(f"/api/findings/{finding.id}/prove")
    assert response.status_code == 409
    assert "not eligible" in response.json()["detail"]


def test_prove_uncertain_returns_409(client):
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    _register_true_positive(client, report, verdict="uncertain")
    finding = next(f for f in report.findings if f.vulnerability_type == "ssrf")
    response = client.post(f"/api/findings/{finding.id}/prove")
    assert response.status_code == 409


def test_prove_unknown_finding_returns_404(client):
    response = client.post("/api/findings/nope/prove")
    assert response.status_code == 404


def test_get_proof_for_unproven_finding_returns_404(client):
    response = client.get("/api/findings/nope/proof")
    assert response.status_code == 404