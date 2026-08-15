"""Read-only proof summary endpoint (GET /api/proof) tests.

The endpoint must never execute proofs or regenerate evidence; it only
aggregates stored ProofResult records and joins finding/validation/risk
context. Only the safe ProofResult subset may be exposed (no payloads,
commands, paths or artifacts).
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.prove.models import ProofResult, SandboxPolicy
from app.prove.service import ProofService
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


def _register_proofs():
    """Scan app.py, validate every finding and prove the true positive."""
    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    for finding in report.findings:
        validation = ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
        ).validate(finding)
        get_validation_store().record(validation)
    results = []
    for finding in report.findings:
        proof = ProofService().prove(
            finding, get_validation_store().get(finding.id)
        )
        assert proof.status == "verified"
        get_proof_store().record(proof)
        results.append(proof)
    return report.findings, results


def _record_controlled_proofs(findings):
    """Insert ProofResults directly with every possible status.

    Statuses are recorded verbatim into the store - the endpoint must
    simply read them back. The first records reuse real finding ids; the
    error record gets its own id so all four statuses always exist.
    """
    statuses = ["verified", "not_verified", "blocked", "error"]
    results = []
    for index, status in enumerate(statuses):
        finding = findings[index] if index < len(findings) else None
        finding_id = finding.id if finding else f"controlled-{status}"
        result = ProofResult(
            finding_id=finding_id,
            vulnerability_type=(
                finding.vulnerability_type if finding else "sql_injection"
            ),
            status=status,
            confidence=0.9 - index * 0.1,
            summary=f"{status} summary",
            duration_ms=1420.0 + index,
            sandbox_policy=SandboxPolicy(
                network_enabled=False,
                allow_loopback=index == 0,
                timeout_seconds=10.0,
                max_output_bytes=16384,
                max_processes=1,
                temporary_directory="/tmp/host-workspace",
                allowed_paths=["/tmp/host-workspace/x"],
            ),
            error=None if status != "error" else "sandbox rejected the harness",
            created_at=FIXED + timedelta(minutes=index),
        )
        get_proof_store().record(result)
        results.append(result)
    return results


def _assess(finding, *, priority, risk_score):
    from app.validate.store import get_validation_store

    validation = get_validation_store().get(finding.id)
    assessment = RiskService().assess(finding, validation).model_copy(
        update={"priority": priority, "risk_score": risk_score}
    )
    record_risk_assessment(assessment)
    return assessment


def test_proof_summary_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/proof"]


def test_proof_summary_only_read_operations(client):
    paths = client.app.openapi()["paths"]["/api/proof"]
    assert set(paths.keys()) == {"get"}


def test_proof_summary_empty(client):
    response = client.get("/api/proof")
    assert response.status_code == 200
    body = response.json()
    assert body["has_findings"] is False
    kpis = body["kpis"]
    assert kpis["total"] == {"available": False, "value": 0}
    assert kpis["verified"] == {"available": False, "value": 0}
    assert kpis["not_verified"] == {"available": False, "value": 0}
    assert kpis["blocked"] == {"available": False, "value": 0}
    assert kpis["errors"] == {"available": False, "value": 0}
    assert body["records"] == []


def test_proof_summary_kpis_for_all_statuses(client):
    findings, _ = _register_proofs()
    _record_controlled_proofs(findings)

    body = client.get("/api/proof").json()
    kpis = body["kpis"]
    assert kpis["total"] == {"available": True, "value": 4}
    assert kpis["verified"] == {"available": True, "value": 1}
    assert kpis["not_verified"] == {"available": True, "value": 1}
    assert kpis["blocked"] == {"available": True, "value": 1}
    assert kpis["errors"] == {"available": True, "value": 1}


def test_proof_summary_real_proof_row(client):
    findings, results = _register_proofs()
    _assess(findings[0], priority="P0", risk_score=95)

    body = client.get("/api/proof").json()
    rows = {row["finding_id"]: row for row in body["records"]}
    assert len(rows) == len(results)

    row = rows[findings[0].id]
    assert row["vulnerability_type"] == findings[0].vulnerability_type
    assert row["severity"] == findings[0].severity
    assert row["priority"] == "P0"
    assert row["validation"] == "true_positive"
    assert row["status"] == "verified"
    assert row["confidence"] == results[0].confidence
    assert row["duration_ms"] == results[0].duration_ms
    assert row["repository"] == "app.py"
    assert row["file"] == findings[0].source.file
    assert row["summary"] == results[0].summary


def test_proof_summary_rows_newest_first(client):
    findings, results = _register_proofs()
    _record_controlled_proofs(findings)
    body = client.get("/api/proof").json()
    expected = sorted(
        (r.created_at for r in get_proof_store().all()), reverse=True
    )
    actual = [datetime.fromisoformat(r["created_at"]) for r in body["records"]]
    assert actual == expected


def test_proof_summary_exposes_only_safe_policy_subset(client):
    findings, _ = _register_proofs()
    _record_controlled_proofs(findings)

    body = client.get("/api/proof").json()
    controlled = next(
        r for r in body["records"] if r["finding_id"] == "controlled-error"
    )
    policy = controlled["sandbox_policy"]
    assert policy is not None
    assert policy["network_enabled"] is False
    assert policy["allow_loopback"] in (True, False)
    assert policy["timeout_seconds"] == 10.0
    assert policy["max_output_bytes"] == 16384
    assert policy["max_processes"] == 1
    # filesystem details are deliberately excluded from the UI boundary
    assert "allowed_paths" not in policy
    assert "temporary_directory" not in policy
    # no payloads, commands or artifacts anywhere in the payload
    assert "artifacts" not in controlled
    assert "evidence" not in controlled


def test_proof_summary_error_text_verbatim(client):
    findings, _ = _register_proofs()
    _record_controlled_proofs(findings)

    body = client.get("/api/proof").json()
    rows = {row["finding_id"]: row for row in body["records"]}
    error_row = next(r for r in rows.values() if r["status"] == "error")
    assert error_row["error"] == "sandbox rejected the harness"
    assert error_row["summary"] == "error summary"


def test_proof_summary_tolerates_missing_finding(client):
    from app.prove.models import ProofResult, SandboxPolicy

    orphan = ProofResult(
        finding_id="ghost",
        vulnerability_type="sql_injection",
        status="blocked",
        confidence=0.5,
        summary="policy blocked the harness",
        duration_ms=200.0,
        sandbox_policy=SandboxPolicy(),
        created_at=FIXED,
    )
    get_proof_store().record(orphan)

    body = client.get("/api/proof").json()
    assert len(body["records"]) == 1
    row = body["records"][0]
    assert row["finding_id"] == "ghost"
    assert row["vulnerability_type"] == "sql_injection"
    assert row["severity"] is None
    assert row["priority"] is None
    assert row["validation"] is None
    assert row["repository"] is None
    assert row["file"] is None


def test_proof_summary_does_not_mutate_stores(client):
    findings, _ = _register_proofs()
    _assess(findings[0], priority="P0", risk_score=95)

    findings_before = [f.model_dump() for f in get_finding_store().all()]
    validations_before = [v.model_dump() for v in get_validation_store().all()]
    proofs_before = [p.model_dump() for p in get_proof_store().all()]

    response = client.get("/api/proof")
    assert response.status_code == 200

    findings_after = [f.model_dump() for f in get_finding_store().all()]
    validations_after = [v.model_dump() for v in get_validation_store().all()]
    proofs_after = [p.model_dump() for p in get_proof_store().all()]
    assert findings_after == findings_before
    assert validations_after == validations_before
    assert proofs_after == proofs_before
