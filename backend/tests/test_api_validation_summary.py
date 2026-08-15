"""Read-only validation summary endpoint (GET /api/validation) tests.

The endpoint must never mutate stores or re-run validation; it only
aggregates stored ValidationResult records and joins finding/risk/proof
context.
"""

from datetime import datetime, timezone

import pytest

from app.prove.store import get_proof_store
from app.risk.service import RiskService, record_risk_assessment
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
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()


def _register_validations():
    """Scan the app.py fixture and validate every finding with mixed verdicts."""
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    verdicts = [
        ("true_positive", 0.94, "taint reaches the sink through the source"),
        ("false_positive", 0.81, "input is sanitized before the sink"),
        ("uncertain", 0.5, "cannot determine reachability without more context"),
    ]
    results = []
    for finding, (verdict, confidence, reasoning) in zip(
        report.findings, verdicts
    ):
        validation = ValidationService(
            provider=FakeLLMProvider(
                verdict=verdict,
                confidence=confidence,
                reasoning=reasoning,
                evidence_used=["taint_path", "sink_snippet"],
            )
        ).validate(finding)
        get_validation_store().record(validation)
        results.append(validation)
    return report.findings, results


def _assess(finding, *, priority, risk_score):
    from app.validate.store import get_validation_store

    validation = get_validation_store().get(finding.id)
    assessment = RiskService().assess(finding, validation).model_copy(
        update={"priority": priority, "risk_score": risk_score}
    )
    record_risk_assessment(assessment)
    return assessment


def test_validation_summary_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/validation"]


def test_validation_summary_only_read_operations(client):
    paths = client.app.openapi()["paths"]["/api/validation"]
    assert set(paths.keys()) == {"get"}


def test_validation_summary_empty(client):
    response = client.get("/api/validation")
    assert response.status_code == 200
    body = response.json()
    assert body["has_findings"] is False
    kpis = body["kpis"]
    assert kpis["total_validations"] == {"available": False, "value": 0}
    assert kpis["true_positives"] == {"available": False, "value": 0}
    assert kpis["false_positives"] == {"available": False, "value": 0}
    assert kpis["uncertain"] == {"available": False, "value": 0}
    assert kpis["pending"] == {"available": False, "value": 0}
    assert body["records"] == []


def test_validation_summary_kpis(client):
    findings, results = _register_validations()
    body = client.get("/api/validation").json()
    kpis = body["kpis"]
    assert kpis["total_validations"] == {"available": True, "value": 3}
    assert kpis["true_positives"] == {"available": True, "value": 1}
    assert kpis["false_positives"] == {"available": True, "value": 1}
    assert kpis["uncertain"] == {"available": True, "value": 1}
    # every scanned finding is validated -> nothing pending
    assert kpis["pending"] == {"available": True, "value": 0}


def test_validation_summary_pending_counts_findings_without_validation(client):
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    finding = report.findings[0]
    validation = ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    ).validate(finding)
    get_validation_store().record(validation)

    body = client.get("/api/validation").json()
    assert body["kpis"]["total_validations"] == {"available": True, "value": 1}
    # 3 findings scanned, 1 validated -> 2 have no validation record yet
    assert body["kpis"]["pending"] == {"available": True, "value": 2}


def test_validation_summary_rows_enriched(client):
    findings, results = _register_validations()
    _assess(findings[0], priority="P0", risk_score=95)
    from app.prove.service import ProofService

    from app.validate.store import get_validation_store

    proof = ProofService().prove(
        findings[0], get_validation_store().get(findings[0].id)
    )
    get_proof_store().record(proof)

    body = client.get("/api/validation").json()
    rows = {row["finding_id"]: row for row in body["records"]}
    assert len(rows) == 3

    tp = rows[findings[0].id]
    assert tp["vulnerability_type"] == findings[0].vulnerability_type
    assert tp["severity"] == findings[0].severity
    assert tp["priority"] == "P0"
    assert tp["repository"] == "app.py"
    assert tp["file"] == findings[0].source.file
    assert tp["confidence"] == 0.94
    assert tp["verdict"] == "true_positive"
    assert tp["proof_status"] == "verified"

    fp = rows[findings[1].id]
    assert fp["verdict"] == "false_positive"
    assert fp["priority"] is None
    assert fp["proof_status"] is None

    assert rows[findings[2].id]["verdict"] == "uncertain"


def test_validation_summary_rows_newest_first(client):
    findings, results = _register_validations()
    body = client.get("/api/validation").json()
    expected = sorted((r.validated_at for r in results), reverse=True)
    actual = [datetime.fromisoformat(r["validated_at"]) for r in body["records"]]
    assert actual == expected


def test_validation_summary_reasoning_and_evidence_verbatim(client):
    findings, results = _register_validations()
    body = client.get("/api/validation").json()
    rows = {row["finding_id"]: row for row in body["records"]}
    row = rows[findings[0].id]
    assert row["reasoning"] == "taint reaches the sink through the source"
    assert row["evidence_used"] == ["taint_path", "sink_snippet"]


def test_validation_summary_tolerates_missing_finding(client):
    from app.validate.models import ValidationResult

    orphan = ValidationResult(
        finding_id="ghost",
        verdict="uncertain",
        confidence=0.4,
        reasoning="no finding context available",
        recommended_next_step="manual_review",
        validated_at=FIXED,
    )
    get_validation_store().record(orphan)

    body = client.get("/api/validation").json()
    assert len(body["records"]) == 1
    row = body["records"][0]
    assert row["finding_id"] == "ghost"
    assert row["vulnerability_type"] is None
    assert row["severity"] is None
    assert row["priority"] is None
    assert row["repository"] is None
    assert row["file"] is None
    assert row["proof_status"] is None


def test_validation_summary_does_not_mutate_stores(client):
    findings, results = _register_validations()
    _assess(findings[0], priority="P0", risk_score=95)

    findings_before = [f.model_dump() for f in get_finding_store().all()]
    validations_before = [v.model_dump() for v in get_validation_store().all()]
    proofs_before = [p.model_dump() for p in get_proof_store().all()]

    response = client.get("/api/validation")
    assert response.status_code == 200

    findings_after = [f.model_dump() for f in get_finding_store().all()]
    validations_after = [v.model_dump() for v in get_validation_store().all()]
    proofs_after = [p.model_dump() for p in get_proof_store().all()]
    assert findings_after == findings_before
    assert validations_after == validations_before
    assert proofs_after == proofs_before
