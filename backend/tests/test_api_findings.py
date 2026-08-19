"""Read-only findings list API tests."""

from datetime import datetime, timedelta, timezone

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


def _assess(finding, priority=None, score=None):
    assessment = RiskService().assess(finding)
    if priority is not None or score is not None:
        assessment = assessment.model_copy(
            update={
                "priority": priority or assessment.priority,
                "risk_score": score if score is not None else assessment.risk_score,
            }
        )
    record_risk_assessment(assessment)
    return assessment


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


def test_findings_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/findings"]


def test_findings_list_empty_store(client):
    response = client.get("/api/findings")
    assert response.status_code == 200
    assert response.json() == []


def test_findings_list_returns_candidate_data(client):
    findings = _register_findings()
    response = client.get("/api/findings")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == len(findings)

    sql = next(f for f in findings if f.vulnerability_type == "sql_injection")
    row = next(r for r in body if r["finding_id"] == sql.id)
    assert row["vulnerability_type"] == "sql_injection"
    assert row["severity"] == sql.severity
    assert row["file"] == sql.source.file
    assert row["source_snippet"] == sql.source.snippet
    assert row["sink_snippet"] == sql.sink.snippet
    assert row["source_kind"] == sql.source.kind
    assert row["sink_kind"] == sql.sink.kind
    assert row["scanner_confidence"] == sql.confidence
    assert row["repository"] == "app.py"
    assert row["priority"] is None
    assert row["verdict"] is None
    assert row["validation_confidence"] is None
    assert row["proof_status"] is None
    assert row["approval_status"] is None
    assert row["sla"] == {
        "status": "none",
        "remaining_seconds": None,
        "priority": None,
    }


def test_findings_list_enriched_with_risk(client):
    sql = _register_findings()[0]
    _assess(sql, priority="P0", score=95)

    row = next(
        r
        for r in client.get("/api/findings").json()
        if r["finding_id"] == sql.id
    )
    assert row["priority"] == "P0"
    assert row["risk_score"] == 95


def test_findings_list_enriched_with_validation_and_proof(client):
    sql = _register_findings()[0]
    proof = _prove(sql)

    row = next(
        r
        for r in client.get("/api/findings").json()
        if r["finding_id"] == sql.id
    )
    assert row["verdict"] == "true_positive"
    assert row["validation_confidence"] == 0.94
    assert row["validated_at"] is not None
    assert row["proof_status"] == proof.status


def test_findings_list_enriched_with_approval(client):
    sql = _register_findings()[0]
    _prove(sql)
    created = client.post(
        f"/api/findings/{sql.id}/approval",
        json={"action": "remediation", "requested_by": "manager"},
    )
    assert created.status_code == 200
    client.post(
        f"/api/approvals/{created.json()['id']}/approve",
        json={"reviewed_by": "security-lead", "reason": "verified"},
    )

    row = next(
        r
        for r in client.get("/api/findings").json()
        if r["finding_id"] == sql.id
    )
    assert row["approval_status"] == "approved"


def test_findings_sla_active_has_remaining_time(client):
    sql = _register_findings()[0]
    assessment = _assess(sql, priority="P1")
    now = datetime.now(timezone.utc)
    sla = SLAService().create_sla(assessment, started_at=now - timedelta(hours=1))
    record_sla_record(sla)

    row = next(
        r
        for r in client.get("/api/findings").json()
        if r["finding_id"] == sql.id
    )
    assert row["sla"]["status"] == "active"
    assert row["sla"]["priority"] == "P1"
    assert row["sla"]["remaining_seconds"] is not None
    assert 0 < row["sla"]["remaining_seconds"] < 24 * 60 * 60


def test_findings_sla_breached_and_resolved(client):
    findings = _register_findings()
    now = datetime.now(timezone.utc)
    for finding, status in zip(findings, ["breached", "resolved"]):
        assessment = _assess(finding, priority="P2")
        if status == "breached":
            sla = SLAService().create_sla(
                assessment, started_at=now - timedelta(days=30)
            )
            record_sla_record(sla)
            breached, _ = SLAService().check_sla(sla, now=now)
            record_sla_record(breached)
        else:
            sla = SLAService().create_sla(
                assessment, started_at=now - timedelta(hours=1)
            )
            record_sla_record(sla)
            record_sla_record(SLAService().resolve_sla(sla))

    rows = {
        r["finding_id"]: r
        for r in client.get("/api/findings").json()
    }
    breached = next(f for f in findings if f.vulnerability_type == "sql_injection")
    resolved = next(
        f for f in findings if f.vulnerability_type == "command_injection"
    )
    unscanned = next(f for f in findings if f.vulnerability_type == "ssrf")
    assert rows[breached.id]["sla"]["status"] == "breached"
    assert rows[resolved.id]["sla"]["status"] == "resolved"
    assert rows[resolved.id]["sla"]["remaining_seconds"] is None
    assert rows[unscanned.id]["sla"] == {
        "status": "none",
        "remaining_seconds": None,
        "priority": None,
    }