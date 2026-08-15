"""Read-only approval review queue (GET /api/approvals) tests.

The queue must never mutate approval state; it only composes the approval,
finding, and risk stores into review rows.
"""

import pytest

from app.approval.service import ApprovalService
from app.approval.store import get_approval_store
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.risk.service import RiskService, record_risk_assessment, reset_risk_stores
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


def _register_finding():
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


def test_approval_queue_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/approvals"]


def test_approval_queue_empty(client):
    response = client.get("/api/approvals")
    assert response.status_code == 200
    assert response.json() == []


def test_approval_queue_lists_requests_with_context(client):
    finding = _register_finding()
    approval = ApprovalService().request_approval(finding.id)
    record_risk_assessment(RiskService().assess(finding))

    response = client.get("/api/approvals")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["approval_id"] == approval.id
    assert row["finding_id"] == finding.id
    assert row["status"] == "pending"
    assert row["action"] == "remediation"
    assert row["version"] == 1
    assert row["requested_by"] == "system"
    assert row["reviewed_by"] is None
    assert row["reviewed_at"] is None
    assert row["reason"] is None
    assert row["vulnerability_type"] == "sql_injection"
    assert row["severity"] == finding.severity
    assert row["priority"] == "P1"
    assert row["risk_score"] == 75
    assert row["repository"] == "app.py"
    assert row["file"] == finding.source.file


def test_approval_queue_reflects_decisions(client):
    finding = _register_finding()
    approval = ApprovalService().request_approval(finding.id)
    ApprovalService().approve(
        approval.id, reviewed_by="security-analyst", reason="Verified."
    )

    row = client.get("/api/approvals").json()[0]
    assert row["status"] == "approved"
    assert row["reviewed_by"] == "security-analyst"
    assert row["reason"] == "Verified."


def test_approval_queue_orders_pending_first_then_newest(client):
    finding = _register_finding()
    first = ApprovalService().request_approval(finding.id)
    second = ApprovalService().request_approval(
        finding.id, action="other", requested_by="analyst"
    )
    ApprovalService().approve(first.id, reviewed_by="lead", reason="ok")

    statuses = [row["status"] for row in client.get("/api/approvals").json()]
    assert statuses == ["pending", "approved"]
    assert client.get("/api/approvals").json()[0]["approval_id"] == second.id


def test_approval_queue_tolerates_missing_finding_and_risk(client):
    finding = _register_finding()
    ApprovalService().request_approval(finding.id)
    get_finding_store().clear()
    reset_risk_stores()

    row = client.get("/api/approvals").json()[0]
    assert row["finding_id"] == finding.id
    assert row["vulnerability_type"] is None
    assert row["severity"] is None
    assert row["priority"] is None
    assert row["risk_score"] is None
    assert row["repository"] is None
    assert row["file"] is None


def test_approval_queue_is_read_only(client):
    finding = _register_finding()
    ApprovalService().request_approval(finding.id)
    client.get("/api/approvals")
    request = get_approval_store().find_for_finding(finding.id)
    assert request.status == "pending"
    assert request.version == 1
