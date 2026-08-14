"""Human approval workflow API tests."""

import pytest

from app.approval.store import get_approval_store
from app.prove.service import ProofService
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
    get_approval_store().clear()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()


def _register_proven_sqli():
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    ).validate(finding)
    proof = ProofService().prove(finding, validation)
    assert proof.status == "verified"
    get_finding_store().add(finding)
    get_validation_store().record(validation)
    get_proof_store().record(proof)
    return finding


def _register_verdict(verdict: str):
    finding = next(
        f
        for f in scan_fixture_files("app.py").findings
        if f.vulnerability_type == "sql_injection"
    )
    validation = ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.9)
    ).validate(finding)
    get_finding_store().add(finding)
    get_validation_store().record(validation)
    return finding


def test_approval_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "post" in paths["/api/findings/{finding_id}/approval"]
    assert "get" in paths["/api/findings/{finding_id}/approval"]
    assert "post" in paths["/api/approvals/{approval_id}/approve"]
    assert "post" in paths["/api/approvals/{approval_id}/reject"]
    assert "post" in paths["/api/approvals/{approval_id}/request-changes"]
    assert "get" in paths["/api/approvals/{approval_id}/history"]


def test_full_approval_workflow_via_api(client):
    finding = _register_proven_sqli()
    created = client.post(
        f"/api/findings/{finding.id}/approval",
        json={"action": "remediation", "requested_by": "system"},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "pending"
    assert body["version"] == 1
    approval_id = body["id"]

    approved = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "security-analyst", "reason": "Verified and proof reviewed."},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["reviewed_by"] == "security-analyst"

    history = client.get(f"/api/approvals/{approval_id}/history")
    assert history.status_code == 200
    events = history.json()
    assert [e["new_status"] for e in events] == ["pending", "approved"]
    assert events[0]["previous_status"] is None
    assert events[1]["previous_status"] == "pending"

    latest = client.get(f"/api/findings/{finding.id}/approval")
    assert latest.json()["status"] == "approved"


def test_rejection_workflow_via_api(client):
    finding = _register_proven_sqli()
    approval_id = client.post(
        f"/api/findings/{finding.id}/approval"
    ).json()["id"]
    rejected = client.post(
        f"/api/approvals/{approval_id}/reject",
        json={"reviewed_by": "security-analyst", "reason": "Risk accepted."},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    history = client.get(f"/api/approvals/{approval_id}/history").json()
    assert history[-1]["new_status"] == "rejected"


def test_changes_workflow_via_api(client):
    finding = _register_proven_sqli()
    approval_id = client.post(
        f"/api/findings/{finding.id}/approval"
    ).json()["id"]
    changed = client.post(
        f"/api/approvals/{approval_id}/request-changes",
        json={"reviewed_by": "analyst", "reason": "Need additional evidence."},
    )
    assert changed.status_code == 200
    assert changed.json()["status"] == "changes_requested"
    resubmitted = client.post(
        f"/api/approvals/{approval_id}/resubmit",
        json={"reviewed_by": "analyst", "reason": "Evidence added."},
    )
    assert resubmitted.status_code == 200
    assert resubmitted.json()["status"] == "pending"
    assert resubmitted.json()["version"] == 2
    approved = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "analyst", "reason": "OK."},
    )
    assert approved.json()["status"] == "approved"


def test_false_positive_cannot_request_approval_409(client):
    finding = _register_verdict("false_positive")
    response = client.post(f"/api/findings/{finding.id}/approval")
    assert response.status_code == 409
    assert "false_positive" in response.json()["detail"]


def test_uncertain_cannot_request_approval_409(client):
    finding = _register_verdict("uncertain")
    response = client.post(f"/api/findings/{finding.id}/approval")
    assert response.status_code == 409
    assert "uncertain" in response.json()["detail"]


def test_validated_but_not_proven_409(client):
    finding = _register_verdict("true_positive")
    response = client.post(f"/api/findings/{finding.id}/approval")
    assert response.status_code == 409
    assert "PROVE" in response.json()["detail"]


def test_unknown_finding_404(client):
    response = client.post("/api/findings/does-not-exist/approval")
    assert response.status_code == 404


def test_unknown_approval_404(client):
    response = client.post(
        "/api/approvals/does-not-exist/approve",
        json={"reviewed_by": "a", "reason": "ok"},
    )
    assert response.status_code == 404


def test_invalid_transition_409(client):
    finding = _register_proven_sqli()
    approval_id = client.post(f"/api/findings/{finding.id}/approval").json()["id"]
    client.post(
        f"/api/approvals/{approval_id}/reject",
        json={"reviewed_by": "a", "reason": "no"},
    )
    response = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "a", "reason": "ok"},
    )
    assert response.status_code == 409
    assert "not allowed" in response.json()["detail"]


def test_missing_reviewer_422(client):
    finding = _register_proven_sqli()
    approval_id = client.post(f"/api/findings/{finding.id}/approval").json()["id"]
    response = client.post(
        f"/api/approvals/{approval_id}/approve", json={"reason": "ok"}
    )
    assert response.status_code == 422


def test_blank_reason_422(client):
    finding = _register_proven_sqli()
    approval_id = client.post(f"/api/findings/{finding.id}/approval").json()["id"]
    response = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "a", "reason": "   "},
    )
    assert response.status_code == 422


def test_get_approval_unknown_finding_404(client):
    response = client.get("/api/findings/does-not-exist/approval")
    assert response.status_code == 404


def test_duplicate_pending_via_api_returns_same(client):
    finding = _register_proven_sqli()
    first = client.post(f"/api/findings/{finding.id}/approval").json()
    second = client.post(f"/api/findings/{finding.id}/approval").json()
    assert second["id"] == first["id"]
    assert second["status"] == "pending"