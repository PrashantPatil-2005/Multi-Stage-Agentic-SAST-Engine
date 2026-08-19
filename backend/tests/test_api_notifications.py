"""Tests for the notifications endpoint (GET /api/notifications)."""

import pytest

from app.approval.store import get_approval_store
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.risk.service import (
    RiskService,
    SLAService,
    record_risk_assessment,
    record_sla_record,
    reset_risk_stores,
)
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
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


def _validate(finding, verdict, confidence=0.9):
    validation = ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=confidence)
    ).validate(finding)
    get_validation_store().record(validation)
    return validation


def _prove(finding):
    validation = _validate(finding, "true_positive", confidence=0.94)
    proof = ProofService().prove(finding, validation)
    get_proof_store().record(proof)
    return proof


def test_notifications_requires_authentication():
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
        response = c.get("/api/notifications")
        assert response.status_code == 401


def test_notifications_empty_when_no_events(client):
    response = client.get("/api/notifications")
    assert response.status_code == 200
    body = response.json()
    assert body["notifications"] == []
    assert body["unread_count"] == 0


def test_notifications_from_validation(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    response = client.get("/api/notifications")
    assert response.status_code == 200
    body = response.json()
    notifs = body["notifications"]
    validation_notifs = [n for n in notifs if n["type"] == "finding_validated"]
    assert len(validation_notifs) >= 1
    assert validation_notifs[0]["finding_id"] == findings[0].id
    assert validation_notifs[0]["read"] is False


def test_notifications_from_proof(client):
    findings = _register_findings()
    _prove(findings[0])
    response = client.get("/api/notifications")
    assert response.status_code == 200
    body = response.json()
    notifs = body["notifications"]
    proof_notifs = [n for n in notifs if n["type"] == "proof_completed"]
    assert len(proof_notifs) >= 1
    assert proof_notifs[0]["finding_id"] == findings[0].id


def test_notifications_from_sla_breach(client):
    findings = _register_findings()
    from datetime import datetime, timedelta, timezone

    assessment = RiskService().assess(findings[0])
    record_risk_assessment(assessment)
    sla = SLAService().create_sla(
        assessment, started_at=datetime.now(timezone.utc) - timedelta(days=30)
    )
    record_sla_record(sla)
    # Force breach
    breached, event = SLAService().check_sla(sla)
    if event:
        from app.risk.service import record_escalation_event
        record_escalation_event(event)
    response = client.get("/api/notifications")
    assert response.status_code == 200
    body = response.json()
    notifs = body["notifications"]
    sla_notifs = [n for n in notifs if n["type"] == "sla_breached"]
    assert len(sla_notifs) >= 1


def test_notifications_unread_count(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    response = client.get("/api/notifications")
    assert response.status_code == 200
    body = response.json()
    assert body["unread_count"] >= 1


def test_mark_notification_read(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    # Get notifications
    response = client.get("/api/notifications")
    notifs = response.json()["notifications"]
    assert len(notifs) >= 1
    notif_id = notifs[0]["id"]
    # Mark as read
    response = client.post(f"/api/notifications/{notif_id}/read")
    assert response.status_code == 200
    # Verify read state
    response = client.get("/api/notifications")
    updated = next(n for n in response.json()["notifications"] if n["id"] == notif_id)
    assert updated["read"] is True


def test_mark_all_notifications_read(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    _prove(findings[1])
    # Mark all read
    response = client.post("/api/notifications/read-all")
    assert response.status_code == 200
    # Verify all read
    response = client.get("/api/notifications")
    body = response.json()
    assert body["unread_count"] == 0
    assert all(n["read"] for n in body["notifications"])


def test_notifications_finding_id_for_navigation(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    response = client.get("/api/notifications")
    notifs = response.json()["notifications"]
    validation_notif = next(n for n in notifs if n["type"] == "finding_validated")
    assert validation_notif["finding_id"] == findings[0].id


def test_notifications_sorted_by_date_desc(client):
    findings = _register_findings()
    _validate(findings[0], "true_positive")
    _prove(findings[1])
    response = client.get("/api/notifications")
    notifs = response.json()["notifications"]
    if len(notifs) >= 2:
        dates = [n["created_at"] for n in notifs]
        assert dates == sorted(dates, reverse=True)
