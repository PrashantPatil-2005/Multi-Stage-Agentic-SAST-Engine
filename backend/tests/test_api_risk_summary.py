"""Read-only risk & SLA summary endpoint (GET /api/risk/summary) tests.

The summary must never mutate stores; it only aggregates existing risk,
SLA, escalation, validation, proof and finding records. Scores and SLA
policy are never recomputed here.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.risk.service import (
    RiskService,
    SLAService,
    all_escalation_events,
    all_risk_assessments,
    all_sla_records,
    record_risk_assessment,
    record_sla_record,
    reset_risk_stores,
)
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files

FIXED = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


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


def _register_findings():
    """Scan, validate and prove all findings from the app.py fixture."""
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    for finding in report.findings:
        validation = ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
        ).validate(finding)
        proof = ProofService().prove(finding, validation)
        assert proof.status == "verified"
        get_validation_store().record(validation)
        get_proof_store().record(proof)
    return report.findings


def _assess(finding, *, priority, risk_score):
    validation = get_validation_store().get(finding.id)
    proof = get_proof_store().get(finding.id)
    assessment = RiskService().assess(finding, validation, proof).model_copy(
        update={"priority": priority, "risk_score": risk_score}
    )
    record_risk_assessment(assessment)
    return assessment


def test_risk_summary_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/risk/summary"]


def test_risk_summary_empty(client):
    response = client.get("/api/risk/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["has_findings"] is False
    assert body["kpis"]["total_assessments"]["available"] is False
    assert body["kpis"]["total_assessments"]["value"] == 0
    assert body["kpis"]["critical_p0"]["available"] is False
    assert body["kpis"]["high_p1"]["available"] is False
    assert body["kpis"]["active_slas"]["available"] is False
    assert body["kpis"]["sla_breaches"]["available"] is False
    assert body["kpis"]["escalations"]["available"] is False
    assert body["priority_distribution"] == []
    assert body["risk_distribution"] == []
    assert body["highest_risk_findings"] == []
    assert body["sla_overview"]["available"] is False
    assert body["active_slas"] == []
    assert body["breaches"] == []
    assert body["escalations"] == []


def test_risk_summary_kpis_and_distributions(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    _assess(findings[1], priority="P1", risk_score=75)
    _assess(findings[2], priority="P3", risk_score=40)

    response = client.get("/api/risk/summary")
    assert response.status_code == 200
    body = response.json()

    kpis = body["kpis"]
    assert kpis["total_assessments"] == {"available": True, "value": 3}
    assert kpis["critical_p0"] == {"available": True, "value": 1}
    assert kpis["high_p1"] == {"available": True, "value": 1}
    assert kpis["active_slas"]["available"] is False
    assert kpis["active_slas"]["value"] == 0
    assert kpis["sla_breaches"]["value"] == 0
    assert kpis["escalations"] == {"available": False, "value": 0}

    assert body["priority_distribution"] == [
        {"priority": "P0", "count": 1, "percent": 33},
        {"priority": "P1", "count": 1, "percent": 33},
        {"priority": "P3", "count": 1, "percent": 33},
    ]
    assert body["risk_distribution"] == [
        {"label": "21-40", "count": 1, "percent": 33},
        {"label": "61-80", "count": 1, "percent": 33},
        {"label": "81-100", "count": 1, "percent": 33},
    ]


def test_risk_summary_highest_risk_ordering(client):
    findings = _register_findings()
    _assess(findings[0], priority="P1", risk_score=90)
    _assess(findings[1], priority="P0", risk_score=60)
    _assess(findings[2], priority="P1", risk_score=95)

    body = client.get("/api/risk/summary").json()
    rows = body["highest_risk_findings"]
    assert [r["finding_id"] for r in rows] == [
        findings[1].id,  # P0 outranks P1 despite the lower score
        findings[2].id,  # P1, higher score first
        findings[0].id,
    ]


def test_risk_summary_highest_risk_row_context(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    sla = SLAService().create_sla(
        all_risk_assessments()[0], started_at=FIXED
    )
    record_sla_record(sla)

    body = client.get("/api/risk/summary").json()
    rows = body["highest_risk_findings"]
    assert len(rows) == 1
    row = rows[0]
    assert row["finding_id"] == findings[0].id
    assert row["priority"] == "P0"
    assert row["risk_score"] == 95
    assert row["severity"] == findings[0].severity
    assert row["vulnerability_type"] == findings[0].vulnerability_type
    assert row["repository"] == "app.py"
    assert row["file"] == findings[0].source.file
    assert row["validation"] == "true_positive"
    assert row["proof"] == "verified"
    assert row["sla"] == "active"
    assert [f["name"] for f in row["factors"]] == ["severity", "validation", "proof"]
    assert row["factors"][0]["points"] > 0


def test_risk_summary_sla_overview_and_active_rows(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    _assess(findings[1], priority="P1", risk_score=75)
    _assess(findings[2], priority="P4", risk_score=10)

    started = datetime.now(timezone.utc) - timedelta(hours=1)
    for assessment in all_risk_assessments():
        record_sla_record(
            SLAService().create_sla(assessment, started_at=started)
        )

    body = client.get("/api/risk/summary").json()
    overview = body["sla_overview"]
    assert overview == {
        "available": True,
        "active": 2,
        "breached": 0,
        "resolved": 0,
        "no_sla": 1,
    }
    assert body["kpis"]["active_slas"] == {"available": True, "value": 2}

    active = body["active_slas"]
    assert len(active) == 2
    p0 = active[0]
    assert p0["priority"] == "P0"
    assert p0["due_at"] is not None
    assert p0["remaining_seconds"] is not None
    # started 1h ago with a 4h deadline -> ~3h remaining snapshot
    assert 10000 <= p0["remaining_seconds"] <= 10800
    assert p0["status"] == "active"
    assert p0["escalation_level"] == 0
    assert p0["breached_at"] is None
    assert active[1]["priority"] == "P1"
    assert active[1]["remaining_seconds"] is not None


def test_risk_summary_active_rows_sorted_by_urgency(client):
    findings = _register_findings()
    _assess(findings[0], priority="P1", risk_score=75)
    _assess(findings[1], priority="P0", risk_score=95)
    for assessment in all_risk_assessments():
        record_sla_record(
            SLAService().create_sla(assessment, started_at=FIXED)
        )
    body = client.get("/api/risk/summary").json()
    assert [row["priority"] for row in body["active_slas"]] == ["P0", "P1"]


def test_risk_summary_breaches(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    record_sla_record(
        SLAService().create_sla(all_risk_assessments()[0], started_at=FIXED)
    )
    updated, event = SLAService().check_sla(
        all_sla_records()[0],
        now=FIXED + timedelta(hours=48),
    )
    record_sla_record(updated)
    from app.risk.service import record_escalation_event

    record_escalation_event(event)

    body = client.get("/api/risk/summary").json()
    assert body["kpis"]["sla_breaches"] == {"available": True, "value": 1}
    assert body["kpis"]["escalations"] == {"available": True, "value": 1}
    assert body["sla_overview"]["breached"] == 1

    breaches = body["breaches"]
    assert len(breaches) == 1
    breach = breaches[0]
    assert breach["status"] == "breached"
    assert breach["escalation_level"] == 1
    assert breach["breached_at"] is not None
    assert breach["remaining_seconds"] is None


def test_risk_summary_escalations_newest_first(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    from app.risk.models import EscalationEvent

    events = [
        EscalationEvent(
            finding_id=findings[0].id,
            previous_level=0,
            new_level=1,
            reason="first breach",
            created_at=FIXED,
        ),
        EscalationEvent(
            finding_id=findings[0].id,
            previous_level=1,
            new_level=2,
            reason="second breach",
            created_at=FIXED + timedelta(hours=1),
        ),
    ]
    for event in events:
        from app.risk.service import record_escalation_event

        record_escalation_event(event)

    body = client.get("/api/risk/summary").json()
    rows = body["escalations"]
    assert [row["new_level"] for row in rows] == [2, 1]
    first = rows[0]
    assert first["finding_id"] == findings[0].id
    assert first["previous_level"] == 1
    assert first["reason"] == "second breach"
    assert first["vulnerability_type"] == findings[0].vulnerability_type
    assert first["priority"] == "P0"


def test_risk_summary_tolerates_missing_optional_data(client):
    # assessment with no finding, and an escalation event with no finding
    from app.risk.models import EscalationEvent, RiskAssessment
    from app.risk.service import record_escalation_event

    orphan_assessment = RiskAssessment(
        finding_id="orphan",
        vulnerability_type="sql_injection",
        severity="high",
        risk_score=95,
        priority="P0",
        factors=[],
        assessed_at=FIXED,
    )
    record_risk_assessment(orphan_assessment)
    record_escalation_event(
        EscalationEvent(
            finding_id="ghost",
            previous_level=0,
            new_level=1,
            reason="breach",
            created_at=FIXED,
        )
    )

    body = client.get("/api/risk/summary").json()
    assert body["kpis"]["total_assessments"] == {"available": True, "value": 1}
    assert body["highest_risk_findings"] == []
    assert body["escalations"][0]["vulnerability_type"] is None
    assert body["escalations"][0]["priority"] is None


def test_risk_summary_does_not_mutate_stores(client):
    findings = _register_findings()
    _assess(findings[0], priority="P0", risk_score=95)
    record_sla_record(
        SLAService().create_sla(all_risk_assessments()[0], started_at=FIXED)
    )
    from app.risk.service import record_escalation_event
    from app.risk.models import EscalationEvent

    record_escalation_event(
        EscalationEvent(
            finding_id=findings[0].id,
            previous_level=0,
            new_level=1,
            reason="breach",
            created_at=FIXED,
        )
    )

    risks_before = [r.model_dump() for r in all_risk_assessments()]
    slas_before = [r.model_dump() for r in all_sla_records()]
    events_before = [e.model_dump() for e in all_escalation_events()]

    response = client.get("/api/risk/summary")
    assert response.status_code == 200

    risks_after = [r.model_dump() for r in all_risk_assessments()]
    slas_after = [r.model_dump() for r in all_sla_records()]
    events_after = [e.model_dump() for e in all_escalation_events()]
    assert risks_after == risks_before
    assert slas_after == slas_before
    assert events_after == events_before
