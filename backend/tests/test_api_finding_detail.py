"""Read-only finding detail API tests (GET /api/findings/{finding_id})."""

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
from tests.scan_test_helpers import FIXTURES, scan_fixture_files, scan_sources

DEDUP_FIXTURES = FIXTURES / "dedup"


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()
    from app.dedup.service import reset_groups

    reset_groups()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()
    from app.dedup.service import reset_groups

    reset_groups()


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


def test_finding_detail_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/findings/{finding_id}"]


def test_finding_detail_missing_finding_404(client):
    response = client.get("/api/findings/does-not-exist")
    assert response.status_code == 404


def test_finding_detail_returns_candidate_data(client):
    sql = _register_findings()[0]
    response = client.get(f"/api/findings/{sql.id}")
    assert response.status_code == 200
    body = response.json()

    assert body["finding_id"] == sql.id
    assert body["vulnerability_type"] == sql.vulnerability_type
    assert body["severity"] == sql.severity
    assert body["scanner_confidence"] == sql.confidence
    assert body["status"] == "candidate"
    assert body["repository"] == "app.py"

    assert body["source"] == {
        "file": sql.source.file,
        "line": sql.source.line,
        "snippet": sql.source.snippet,
        "kind": sql.source.kind,
    }
    assert body["sink"] == {
        "file": sql.sink.file,
        "line": sql.sink.line,
        "snippet": sql.sink.snippet,
        "kind": sql.sink.kind,
    }
    assert body["taint_path"] == [
        {
            "file": step.file,
            "line": step.line,
            "snippet": step.snippet,
            "step_type": step.step_type,
        }
        for step in sql.taint_path
    ]

    assert body["risk"] is None
    assert body["sla"] is None
    assert body["validation"] is None
    assert body["proof"] is None
    assert body["approval"] is None
    assert body["dedup"] is None


def test_finding_detail_enriched_with_risk(client):
    sql = _register_findings()[0]
    _assess(sql, priority="P0", score=95)

    body = client.get(f"/api/findings/{sql.id}").json()
    assert body["risk"]["priority"] == "P0"
    assert body["risk"]["risk_score"] == 95
    assert body["risk"]["finding_id"] == sql.id
    assert any(
        factor["name"] == "severity" for factor in body["risk"]["factors"]
    )


def test_finding_detail_enriched_with_validation(client):
    sql = _register_findings()[0]
    _validate(sql, "true_positive", confidence=0.94)

    body = client.get(f"/api/findings/{sql.id}").json()
    validation = body["validation"]
    assert validation["verdict"] == "true_positive"
    assert validation["confidence"] == 0.94
    assert validation["reasoning"]
    assert validation["validated_at"] is not None
    assert validation["evidence_used"] is not None


def test_finding_detail_proof_exposes_only_safe_summary(client):
    sql = _register_findings()[0]
    proof = _prove(sql)

    body = client.get(f"/api/findings/{sql.id}").json()
    exposed = body["proof"]
    assert exposed["status"] == proof.status
    assert exposed["summary"] == proof.summary
    assert exposed["created_at"] is not None
    assert "artifacts" not in exposed
    assert "evidence" not in exposed
    assert "input_value" not in exposed
    assert exposed["sandbox_policy"] is not None
    assert "temporary_directory" in exposed["sandbox_policy"]


def test_finding_detail_enriched_with_approval(client):
    sql = _register_findings()[0]
    _prove(sql)
    created = client.post(
        f"/api/findings/{sql.id}/approval",
        json={"action": "remediation", "requested_by": "manager"},
    )
    assert created.status_code == 200
    client.post(
        f"/api/approvals/{created.json()['id']}/approve",
        json={"reason": "verified"},
    )

    body = client.get(f"/api/findings/{sql.id}").json()
    assert body["approval"]["status"] == "approved"
    assert body["approval"]["requested_by"] == "manager"
    assert body["approval"]["reviewed_by"] == "manager"
    assert body["approval"]["reason"] == "verified"


def test_finding_detail_sla_active_remaining_seconds(client):
    sql = _register_findings()[0]
    assessment = _assess(sql, priority="P1")
    now = datetime.now(timezone.utc)
    sla = SLAService().create_sla(assessment, started_at=now - timedelta(hours=1))
    record_sla_record(sla)

    body = client.get(f"/api/findings/{sql.id}").json()
    assert body["sla"]["status"] == "active"
    assert body["sla"]["priority"] == "P1"
    assert body["sla"]["escalation_level"] == 0
    assert body["sla"]["remaining_seconds"] is not None
    assert 0 < body["sla"]["remaining_seconds"] < 24 * 60 * 60


def test_finding_detail_sla_breached_escalation(client):
    sql = _register_findings()[0]
    assessment = _assess(sql, priority="P2")
    now = datetime.now(timezone.utc)
    sla = SLAService().create_sla(assessment, started_at=now - timedelta(days=30))
    breached, event = SLAService().check_sla(sla, now=now)
    record_sla_record(breached)
    assert event is not None

    body = client.get(f"/api/findings/{sql.id}").json()
    assert body["sla"]["status"] == "breached"
    assert body["sla"]["breached_at"] is not None
    assert body["sla"]["escalation_level"] == 1


def _register_cross_repo():
    """Two repositories with equivalent findings -> one dedup group."""
    sources = {
        "repository_a/views.py": (
            DEDUP_FIXTURES / "repository_a" / "views.py"
        ).read_text(encoding="utf-8"),
        "repository_b/main.py": (
            DEDUP_FIXTURES / "repository_b" / "main.py"
        ).read_text(encoding="utf-8"),
    }
    report = scan_sources(sources)
    get_finding_store().add_report(report)
    return report


def test_finding_detail_dedup_canonical(client):
    report = _register_cross_repo()
    ids = [f.id for f in report.findings]
    client.post("/api/deduplicate", json={"finding_ids": ids})

    canonical = min(ids)
    body = client.get(f"/api/findings/{canonical}").json()
    assert body["dedup"] is not None
    assert body["dedup"]["is_canonical"] is True
    assert body["dedup"]["canonical_finding_id"] == canonical
    assert body["dedup"]["occurrence_count"] == len(ids)
    assert body["dedup"]["fingerprint"]
    assert body["dedup"]["structural_signature"]
    assert sorted(body["dedup"]["related_finding_ids"]) == sorted(
        [fid for fid in ids if fid != canonical]
    )


def test_finding_detail_dedup_member_is_not_canonical(client):
    report = _register_cross_repo()
    ids = [f.id for f in report.findings]
    client.post("/api/deduplicate", json={"finding_ids": ids})

    canonical = min(ids)
    member = max(ids)
    body = client.get(f"/api/findings/{member}").json()
    assert body["dedup"] is not None
    assert body["dedup"]["is_canonical"] is False
    assert body["dedup"]["canonical_finding_id"] == canonical
    assert member not in body["dedup"]["related_finding_ids"]
    assert canonical in body["dedup"]["related_finding_ids"]
    assert body["dedup"]["occurrence_count"] == len(ids)


def test_finding_detail_no_dedup_group(client):
    sql = _register_findings()[0]
    body = client.get(f"/api/findings/{sql.id}").json()
    assert body["dedup"] is None
