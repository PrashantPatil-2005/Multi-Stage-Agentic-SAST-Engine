"""Risk/SLA API endpoint tests (fixed clocks, FakeLLMProvider only)."""

from datetime import datetime, timedelta, timezone

import pytest

from app.prove.store import get_proof_store
from app.risk.service import get_escalation_events, get_risk_assessment, get_sla_record, reset_risk_stores
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files

FIXED = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    reset_risk_stores()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    reset_risk_stores()


@pytest.fixture
def registered_sqli():
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    return next(f for f in report.findings if f.vulnerability_type == "sql_injection")


def test_risk_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "post" in paths["/api/findings/{finding_id}/risk"]
    assert "get" in paths["/api/findings/{finding_id}/risk"]
    assert "post" in paths["/api/findings/{finding_id}/sla"]
    assert "get" in paths["/api/findings/{finding_id}/sla"]
    assert "post" in paths["/api/findings/{finding_id}/sla/check"]
    assert "post" in paths["/api/findings/{finding_id}/sla/resolve"]
    assert "get" in paths["/api/findings/{finding_id}/escalations"]


def test_post_risk_returns_and_stores_assessment(client, registered_sqli):
    response = client.post(f"/api/findings/{registered_sqli.id}/risk")
    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == registered_sqli.id
    assert body["risk_score"] == 75
    assert body["priority"] == "P1"
    assert body["severity"] == "high"
    assert get_risk_assessment(registered_sqli.id) is not None
    get_response = client.get(f"/api/findings/{registered_sqli.id}/risk")
    assert get_response.json()["risk_score"] == 75


def test_post_risk_unknown_finding_404(client):
    response = client.post("/api/findings/does-not-exist/risk")
    assert response.status_code == 404


def test_get_risk_unassessed_404(client, registered_sqli):
    response = client.get(f"/api/findings/{registered_sqli.id}/risk")
    assert response.status_code == 404


def test_post_sla_requires_risk_404(client, registered_sqli):
    response = client.post(f"/api/findings/{registered_sqli.id}/sla")
    assert response.status_code == 404


def test_post_sla_creates_record(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    response = client.post(f"/api/findings/{registered_sqli.id}/sla")
    assert response.status_code == 200
    body = response.json()
    assert body["priority"] == "P1"
    assert body["status"] == "active"
    due = datetime.fromisoformat(body["due_at"])
    started = datetime.fromisoformat(body["started_at"])
    assert due - started == timedelta(hours=24)
    assert get_sla_record(registered_sqli.id) is not None
    get_response = client.get(f"/api/findings/{registered_sqli.id}/sla")
    assert get_response.status_code == 200


def test_post_sla_is_idempotent(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    first = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    second = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    assert first["started_at"] == second["started_at"]
    assert first["due_at"] == second["due_at"]


def test_post_check_breaches_and_escalates_once(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    sla = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    started = datetime.fromisoformat(sla["started_at"])
    now = (started + timedelta(hours=30)).isoformat()
    response = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check", json={"now": now}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["sla"]["status"] == "breached"
    assert body["escalation"]["new_level"] == 1
    repeat = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": (started + timedelta(hours=40)).isoformat()},
    )
    assert repeat.json()["escalation"] is None
    assert len(get_escalation_events(registered_sqli.id)) == 1


def test_post_check_naive_time_422(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    client.post(f"/api/findings/{registered_sqli.id}/sla")
    response = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": "2026-01-02T06:00:00"},
    )
    assert response.status_code == 422


def test_post_resolve_and_stays_resolved(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    sla = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    started = datetime.fromisoformat(sla["started_at"])
    resolved = (started + timedelta(hours=5)).isoformat()
    response = client.post(
        f"/api/findings/{registered_sqli.id}/sla/resolve",
        json={"resolved_at": resolved},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "resolved"
    assert datetime.fromisoformat(response.json()["resolved_at"]) == datetime.fromisoformat(
        resolved
    )
    later = client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": (started + timedelta(days=3)).isoformat()},
    )
    assert later.json()["sla"]["status"] == "resolved"


def test_post_sla_check_missing_sla_404(client, registered_sqli):
    response = client.post(f"/api/findings/{registered_sqli.id}/sla/check")
    assert response.status_code == 404


def test_get_escalations(client, registered_sqli):
    client.post(f"/api/findings/{registered_sqli.id}/risk")
    sla = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    started = datetime.fromisoformat(sla["started_at"])
    response = client.get(f"/api/findings/{registered_sqli.id}/escalations")
    assert response.status_code == 200
    assert response.json() == []
    client.post(
        f"/api/findings/{registered_sqli.id}/sla/check",
        json={"now": (started + timedelta(hours=30)).isoformat()},
    )
    events = client.get(f"/api/findings/{registered_sqli.id}/escalations").json()
    assert len(events) == 1
    assert events[0]["previous_level"] == 0
    assert events[0]["new_level"] == 1


def test_false_positive_gets_p4_no_sla(client, registered_sqli):
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="false_positive", confidence=0.9)
    ).validate(registered_sqli)
    get_validation_store().record(validation)
    risk = client.post(f"/api/findings/{registered_sqli.id}/risk").json()
    assert risk["risk_score"] == 0
    assert risk["priority"] == "P4"
    sla = client.post(f"/api/findings/{registered_sqli.id}/sla").json()
    assert sla["status"] == "not_applicable"
    assert sla["due_at"] is None