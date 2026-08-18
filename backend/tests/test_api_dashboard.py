"""Read-only dashboard summary API tests."""

from datetime import datetime, timedelta, timezone

import pytest

from app.approval.store import get_approval_store
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.risk.service import (
    RiskService,
    SLAService,
    all_escalation_events,
    record_escalation_event,
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


def _scan_findings():
    return scan_fixture_files("app.py").findings


def _register_finding(finding):
    get_finding_store().add(finding)
    return finding


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


def _validate(finding, verdict):
    validation = ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.9)
    ).validate(finding)
    get_validation_store().record(validation)
    return validation


def _prove(finding):
    validation = _validate(finding, "true_positive")
    proof = ProofService().prove(finding, validation)
    get_proof_store().record(proof)
    return proof


def test_dashboard_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/dashboard/summary"]
    assert "get" in paths["/api/projects"]


def test_summary_with_empty_stores(client):
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["projects"] == []
    for key, kpi in body["kpis"].items():
        assert kpi == {"available": False, "value": 0}
    for stage in body["pipeline"]:
        assert stage["count"] is None
    assert body["critical_findings"] == []
    assert body["sla"] == {
        "available": False,
        "active": 0,
        "breached": 0,
        "highest_priority_breach": None,
        "escalation_count": 0,
    }
    assert body["verification"]["available"] is False
    assert body["recent_activity"] == []


def test_projects_list_empty_then_populated(client, fixture_repo):
    assert client.get("/api/projects").json() == []

    created = client.post(
        "/api/projects",
        json={
            "name": "demo-app",
            "source_type": "directory",
            "location": str(fixture_repo),
            "language": "python",
        },
    )
    assert created.status_code == 201

    listing = client.get("/api/projects").json()
    assert len(listing) == 1
    assert listing[0]["name"] == "demo-app"
    assert listing[0]["id"] == created.json()["id"]

    summary = client.get("/api/dashboard/summary").json()
    assert summary["projects"] == listing
    assert summary["pipeline"][0]["stage"] == "PREPARE"
    assert summary["pipeline"][0]["count"] == 1
    assert summary["kpis"]["total_findings"]["available"] is False


def test_summary_kpis_and_pipeline_with_seeded_data(client):
    findings = _scan_findings()
    sql_finding = _register_finding(findings[0])
    cmd_finding = _register_finding(findings[1])
    ssrf_finding = _register_finding(findings[2])
    _assess(sql_finding, priority="P0", score=95)
    _assess(cmd_finding, priority="P1", score=75)
    _assess(ssrf_finding, priority="P2", score=60)
    _validate(cmd_finding, "false_positive")
    _prove(sql_finding)

    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    body = response.json()

    assert body["kpis"]["total_findings"] == {"available": True, "value": 3}
    assert body["kpis"]["critical_p0"] == {"available": True, "value": 1}
    assert body["kpis"]["pending_validation"] == {"available": True, "value": 1}
    assert body["kpis"]["pending_approval"] == {"available": True, "value": 0}

    stages = {stage["stage"]: stage for stage in body["pipeline"]}
    assert stages["SCAN"]["count"] == 3
    assert stages["RISK"]["count"] == 3
    assert stages["VALIDATE"]["count"] == 2
    assert stages["PROVE"]["count"] == 1

    critical = body["critical_findings"]
    assert len(critical) == 3
    assert critical[0]["finding_id"] == sql_finding.id
    assert critical[0]["priority"] == "P0"
    assert critical[0]["status"] == "verified"
    assert critical[1]["priority"] == "P1"
    assert critical[1]["status"] == "false positive"

    assert body["verification"] == {
        "available": True,
        "true_positive": 1,
        "false_positive": 1,
        "uncertain": 0,
        "verified": 1,
        "not_verified": 0,
        "blocked": 0,
        "errors": 0,
    }

    kinds = [item["kind"] for item in body["recent_activity"]]
    assert "finding_validated" in kinds
    assert "proof_completed" in kinds


def test_critical_findings_sorted_by_priority_and_capped_at_five(client):
    findings = _scan_findings()
    registered = [_register_finding(f) for f in findings]
    priorities = ["P2", "P1", "P0"]
    for finding, priority in zip(registered, priorities):
        _assess(finding, priority=priority, score=50)

    extra = scan_fixture_files("db.py").findings
    for finding in extra:
        _register_finding(finding)
        _assess(finding, priority="P4", score=20)

    body = client.get("/api/dashboard/summary").json()
    critical = body["critical_findings"]
    assert len(critical) == 5
    assert [row["priority"] for row in critical] == [
        "P0",
        "P1",
        "P2",
        "P4",
        "P4",
    ]
    assert body["kpis"]["total_findings"]["value"] == 5


def test_sla_summary_with_breaches_and_escalations(client):
    findings = _scan_findings()
    now = datetime.now(timezone.utc)
    priority_to_breach = {}
    for finding, priority in zip(findings, ["P1", "P0"]):
        _register_finding(finding)
        assessment = _assess(finding, priority=priority)
        sla = SLAService().create_sla(
            assessment, started_at=now - timedelta(days=30)
        )
        record_sla_record(sla)
        record, event = SLAService().check_sla(sla, now=now)
        record_sla_record(record)
        if event is not None:
            record_escalation_event(event)
            priority_to_breach[priority] = record

    assert len(all_escalation_events()) == 2
    body = client.get("/api/dashboard/summary").json()
    assert body["kpis"]["sla_breaches"] == {"available": True, "value": 2}
    assert body["sla"]["active"] == 0
    assert body["sla"]["breached"] == 2
    assert body["sla"]["highest_priority_breach"] == "P0"
    assert body["sla"]["escalation_count"] == 2
    assert "sla_breached" in [item["kind"] for item in body["recent_activity"]]


def test_pending_approval_kpi_and_activity(client):
    finding = _register_finding(_scan_findings()[0])
    _prove(finding)
    created = client.post(
        f"/api/findings/{finding.id}/approval",
        json={"action": "remediation", "requested_by": "system"},
    )
    assert created.status_code == 200
    approval_id = created.json()["id"]

    client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "security-lead", "reason": "verified"},
    )

    body = client.get("/api/dashboard/summary").json()
    assert body["kpis"]["pending_approval"] == {"available": True, "value": 0}
    assert "approval_updated" in [item["kind"] for item in body["recent_activity"]]


def test_recent_activity_mixes_db_projects_and_in_memory_events(client, fixture_repo):
    created = client.post(
        "/api/projects",
        json={
            "name": "demo-app",
            "source_type": "directory",
            "location": str(fixture_repo),
            "language": "python",
        },
    )
    assert created.status_code == 201

    finding = _register_finding(_scan_findings()[0])
    _validate(finding, "true_positive")

    body = client.get("/api/dashboard/summary").json()
    assert [item["kind"] for item in body["recent_activity"]] == [
        "finding_validated",
        "project_created",
    ]