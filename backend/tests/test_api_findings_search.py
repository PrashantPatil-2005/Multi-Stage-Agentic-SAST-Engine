"""Tests for the findings search parameter (GET /api/findings?search=...)."""

import pytest

from app.approval.store import get_approval_store
from app.prove.store import get_proof_store
from app.risk.service import (
    reset_risk_stores,
)
from app.validate.store import get_finding_store, get_validation_store
from tests.scan_test_helpers import scan_fixture_files


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()


def _register_findings():
    findings = scan_fixture_files("app.py").findings
    for finding in findings:
        get_finding_store().add(finding)
    return findings


def test_search_empty_query_returns_all(client):
    _register_findings()
    response = client.get("/api/findings?search=")
    assert response.status_code == 200
    assert len(response.json()) > 0


def test_search_no_param_returns_all(client):
    _register_findings()
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert len(response.json()) > 0


def test_search_by_vulnerability_type(client):
    _register_findings()
    response = client.get("/api/findings?search=sql_injection")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 1
    assert all("sql_injection" in r["vulnerability_type"] for r in body)


def test_search_by_finding_id(client):
    findings = _register_findings()
    target = findings[0]
    response = client.get(f"/api/findings?search={target.id[:8]}")
    assert response.status_code == 200
    body = response.json()
    assert any(r["finding_id"] == target.id for r in body)


def test_search_by_file(client):
    _register_findings()
    response = client.get("/api/findings?search=app.py")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 1
    assert all("app.py" in r["file"] for r in body)


def test_search_by_severity(client):
    _register_findings()
    response = client.get("/api/findings?search=HIGH")
    assert response.status_code == 200


def test_search_no_results(client):
    _register_findings()
    response = client.get("/api/findings?search=zzz_nonexistent_xyz")
    assert response.status_code == 200
    assert response.json() == []


def test_search_with_project_scope(client):
    _register_findings()
    response = client.get("/api/findings?search=sql_injection")
    assert response.status_code == 200


def test_search_requires_authentication():
    """Unauthenticated requests are rejected."""
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.main import create_app

    settings = Settings(
        workspace_dir="/tmp/test_workspace",
        database_url="sqlite:///:memory:",
        log_level="WARNING",
    )
    app = create_app(settings)
    with TestClient(app) as c:
        response = c.get("/api/findings?search=test")
        assert response.status_code == 401


def test_search_case_insensitive(client):
    _register_findings()
    response = client.get("/api/findings?search=SQL_INJECTION")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 1
