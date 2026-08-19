"""End-to-end security pipeline verification.

One controlled fixture (tests/fixtures/vulnerable_python_app) flows through
the REAL application services:

    PREPARE -> SCAN -> DEDUP -> RISK/SLA -> VALIDATE -> PROVE -> APPROVAL

Offline tests are deterministic (FakeLLMProvider). The real Hugging Face
smoke test carries ``@pytest.mark.llm_smoke`` and skips when LLM
configuration is absent - it is never part of the mandatory offline suite.

No real credentials, no external network in offline tests, no exploit
execution beyond the existing approved proof harnesses.
"""

import os

import httpx
import pytest
from httpx import MockTransport

from app.api.routes.validations import get_validation_service
from app.approval.store import get_approval_store
from app.dedup.service import reset_groups
from app.prove.store import get_proof_store
from app.risk.service import reset_risk_stores
from app.validate.providers.base import ConfigurationError
from app.validate.providers.huggingface import HuggingFaceLLMProvider
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files

VALID_VERDICTS = {"true_positive", "false_positive", "uncertain"}


@pytest.fixture(autouse=True)
def clean_pipeline_stores():
    stores = (
        get_finding_store,
        get_validation_store,
        get_proof_store,
        get_approval_store,
    )
    for store in stores:
        store().clear()
    reset_risk_stores()
    reset_groups()
    yield
    for store in stores:
        store().clear()
    reset_risk_stores()
    reset_groups()


@pytest.fixture
def fake_validation(client):
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    )
    yield client
    app.dependency_overrides.clear()


def _register_report(report):
    get_finding_store().add_report(report)


def test_full_pipeline_prepare_to_approval(fake_validation, client, fixture_repo):
    """The complete chain through the real API with a deterministic verdict."""
    # ---- PREPARE ------------------------------------------------------
    resp = client.post(
        "/api/projects",
        json={
            "name": "e2e-app",
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    )
    assert resp.status_code == 201
    project = resp.json()
    assert project["status"] == "prepared"
    assert project["summary"]["python_files"] == 7
    assert project["summary"]["parse_failures"] == 1
    detail = client.get(f"/api/projects/{project['id']}")
    assert detail.status_code == 200
    files = {f["path"]: f for f in detail.json()["files"]}
    assert files["app.py"]["error"] is None
    assert files["bad_syntax.py"]["error"] is not None

    # ---- SCAN (real scanner, no fabricated finding) -------------------
    report = scan_fixture_files("app.py", "db.py")
    _register_report(report)
    sql = next(f for f in report.findings if f.vulnerability_type == "sql_injection")
    fid = sql.id
    assert sql.source is not None
    assert sql.sink is not None
    assert len(sql.taint_path) >= 2
    assert 0.0 <= sql.confidence <= 1.0

    # ---- DEDUP ---------------------------------------------------------
    ids = [f.id for f in report.findings]
    dedup = client.post("/api/deduplicate", json={"finding_ids": ids})
    assert dedup.status_code == 200
    body = dedup.json()
    assert body["total_findings"] == len(ids)
    assert body["unique_findings"] <= body["total_findings"]
    assert sum(g["occurrence_count"] for g in body["groups"]) == body["total_findings"]
    group = next(g for g in body["groups"] if fid in g["member_finding_ids"])
    assert group["fingerprint"]
    assert group["structural_signature"]
    assert group["canonical_finding_id"] in group["member_finding_ids"]
    assert group["occurrence_count"] >= 1

    # ---- VALIDATE ------------------------------------------------------
    validation = client.post(
        f"/api/findings/{fid}/validate", json={"provider": "huggingface"}
    )
    assert validation.status_code == 200
    v = validation.json()
    assert v["finding_id"] == fid
    assert v["verdict"] in VALID_VERDICTS
    assert 0.0 <= v["confidence"] <= 1.0
    assert v["reasoning"]
    assert v["evidence_used"]
    assert v["recommended_next_step"] in {"prove", "discard", "manual_review"}
    assert v["model"] == "fake-model"
    assert v["validated_at"]

    # ---- RISK ----------------------------------------------------------
    risk = client.post(f"/api/findings/{fid}/risk")
    assert risk.status_code == 200
    r = risk.json()
    assert r["finding_id"] == fid
    assert 0 <= r["risk_score"] <= 100
    assert r["priority"] in {"P0", "P1", "P2", "P3", "P4"}
    assert r["severity"] == sql.severity
    assert r["factors"]

    # ---- SLA -----------------------------------------------------------
    sla = client.post(f"/api/findings/{fid}/sla")
    assert sla.status_code == 200
    s = sla.json()
    assert s["finding_id"] == fid
    assert s["status"] in {"not_applicable", "active", "breached", "resolved"}
    assert s["priority"] == r["priority"]
    assert s["started_at"]
    assert s["due_at"] or s["status"] == "not_applicable"
    assert s["escalation_level"] == 0

    # ---- PROVE (real sandbox, approved harness only) -------------------
    proof = client.post(f"/api/findings/{fid}/prove")
    assert proof.status_code == 200
    p = proof.json()
    assert p["finding_id"] == fid
    assert p["status"] == "verified"
    assert p["confidence"] == 0.94
    assert p["summary"]
    assert p["duration_ms"] is not None
    assert p["created_at"]
    assert p["sandbox_policy"]["network_enabled"] is False
    assert p["sandbox_policy"]["max_processes"] == 1

    # ---- APPROVAL ------------------------------------------------------
    approval = client.post(f"/api/findings/{fid}/approval")
    assert approval.status_code == 200
    a = approval.json()
    approval_id = a["id"]
    assert a["finding_id"] == fid
    assert a["status"] == "pending"
    assert a["requested_at"]
    assert a["requested_by"] == "manager"

    decided = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reason": "controlled e2e decision"},
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    # reviewed_by is now derived from the authenticated user
    assert decided.json()["reviewed_by"] == "manager"
    history = client.get(f"/api/approvals/{approval_id}/history")
    assert history.status_code == 200
    assert len(history.json()) >= 2

    # ---- COMPOSED READS -------------------------------------------------
    detail_f = client.get(f"/api/findings/{fid}")
    assert detail_f.status_code == 200
    d = detail_f.json()
    assert d["finding_id"] == fid
    assert d["risk"]["finding_id"] == fid
    assert d["sla"]["status"] == s["status"]
    assert d["sla"]["priority"] == r["priority"]
    assert d["validation"]["finding_id"] == fid
    assert d["proof"]["status"] == "verified"
    assert d["approval"]["finding_id"] == fid
    assert d["dedup"]["fingerprint"] == group["fingerprint"]
    assert d["source"]["snippet"]
    assert d["sink"]["snippet"]
    assert d["taint_path"]

    listed = client.get("/api/findings")
    assert listed.status_code == 200
    item = next(i for i in listed.json() if i["finding_id"] == fid)
    assert item["verdict"] == "true_positive"
    assert item["proof_status"] == "verified"
    assert item["approval_status"] == "approved"


def test_finding_id_identical_across_all_stages(fake_validation, client):
    """The same backend finding id flows through every record, unchanged."""
    report = scan_fixture_files("app.py")
    _register_report(report)
    fid = next(f for f in report.findings if f.vulnerability_type == "sql_injection").id

    client.post("/api/deduplicate", json={"finding_ids": [f.id for f in report.findings]})
    client.post(f"/api/findings/{fid}/validate", json={})
    client.post(f"/api/findings/{fid}/risk")
    client.post(f"/api/findings/{fid}/sla")
    client.post(f"/api/findings/{fid}/prove")
    approval = client.post(f"/api/findings/{fid}/approval").json()

    candidate = get_finding_store().get(fid)
    validation = get_validation_store().get(fid)
    proof = get_proof_store().get(fid)
    from app.approval.store import get_approval_store

    approval_record = get_approval_store().get(approval["id"])
    from app.risk.service import get_risk_assessment, get_sla_record

    risk = get_risk_assessment(fid)
    sla = get_sla_record(fid)

    assert candidate is not None and candidate.id == fid
    assert validation is not None and validation.finding_id == fid
    assert proof is not None and proof.finding_id == fid
    assert approval_record is not None and approval_record.finding_id == fid
    assert risk is not None and risk.finding_id == fid
    assert sla is not None and sla.finding_id == fid


def test_no_llm_key_returns_safe_503_without_fabricated_record(
    client, monkeypatch, fixture_repo
):
    """Missing LLM config -> 503; no ValidationResult; the app stays usable."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    report = scan_fixture_files("app.py")
    _register_report(report)
    fid = next(f for f in report.findings if f.vulnerability_type == "sql_injection").id

    response = client.post(f"/api/findings/{fid}/validate", json={})
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]

    stored = client.get(f"/api/findings/{fid}/validation")
    assert stored.status_code == 404

    findings = client.get("/api/findings")
    assert findings.status_code == 200


def test_llm_failure_returns_safe_503_without_fabricated_record(client):
    """Provider failure -> 503; no fabricated verdict; token never exposed."""

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=HuggingFaceLLMProvider(
            base_url="https://router.huggingface.co/v1",
            api_key="test-token-never-real",
            model="test-model",
            transport=MockTransport(offline),
        )
    )
    report = scan_fixture_files("app.py")
    _register_report(report)
    fid = next(f for f in report.findings if f.vulnerability_type == "sql_injection").id
    try:
        response = client.post(f"/api/findings/{fid}/validate", json={})
        assert response.status_code == 503
        assert "LLM validation is currently unavailable" in response.json()["detail"]
        assert "test-token-never-real" not in response.text
        assert get_validation_store().get(fid) is None
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def llm_smoke_selected(pytestconfig):
    """True only when the suite is explicitly run with `-m llm_smoke`."""
    marker = pytestconfig.getoption("-m") or ""
    return "llm_smoke" in marker


@pytest.mark.llm_smoke
def test_real_hugging_face_pipeline_smoke(client, fixture_repo, llm_smoke_selected):
    """ONE explicit real-LLM E2E run. Only with `-m llm_smoke` + config.

    Never prints the token. The verdict is whatever the model returns; the
    test verifies the contract, then continues to PROVE + APPROVAL only when
    the model produced true_positive (otherwise the existing proof gate is
    asserted as a valid system result).
    """
    if not llm_smoke_selected:
        pytest.skip("not selected (run with -m llm_smoke)")
    if not os.getenv("LLM_API_KEY") or not os.getenv("LLM_MODEL"):
        pytest.skip("LLM_API_KEY / LLM_MODEL not configured; real smoke test skipped")

    # ---- PREPARE ------------------------------------------------------
    resp = client.post(
        "/api/projects",
        json={
            "name": "e2e-smoke",
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    )
    assert resp.status_code == 201
    project = resp.json()
    assert project["status"] == "prepared"

    # ---- SCAN -> DEDUP -> RISK -> SLA ---------------------------------
    report = scan_fixture_files("app.py")
    _register_report(report)
    sql = next(f for f in report.findings if f.vulnerability_type == "sql_injection")
    fid = sql.id
    client.post("/api/deduplicate", json={"finding_ids": [f.id for f in report.findings]})

    # ---- REAL VALIDATION (no provider override -> real Hugging Face) --
    response = client.post(
        f"/api/findings/{fid}/validate", json={"provider": "huggingface"}
    )
    assert response.status_code == 200
    v = response.json()
    assert v["finding_id"] == fid
    assert v["verdict"] in VALID_VERDICTS
    assert 0.0 <= v["confidence"] <= 1.0
    assert v["reasoning"]
    assert v["model"]
    assert v["validated_at"]
    print(
        f"\n[llm-smoke] finding={fid} vuln=sql_injection "
        f"verdict={v['verdict']} confidence={v['confidence']} "
        f"model={v['model']} validated_at={v['validated_at']}"
    )

    risk = client.post(f"/api/findings/{fid}/risk")
    assert risk.status_code == 200
    sla = client.post(f"/api/findings/{fid}/sla")
    assert sla.status_code == 200

    if v["verdict"] != "true_positive":
        gate = client.post(f"/api/findings/{fid}/prove")
        assert gate.status_code == 409
        print("[llm-smoke] proof gate: verdict is not true_positive -> 409 (valid)")
        return

    # ---- PROVE (real sandbox) -----------------------------------------
    proof = client.post(f"/api/findings/{fid}/prove")
    assert proof.status_code == 200
    p = proof.json()
    assert p["finding_id"] == fid
    assert p["status"] == "verified"
    assert p["sandbox_policy"]["network_enabled"] is False
    print(
        f"[llm-smoke] proof status={p['status']} duration_ms={p['duration_ms']} "
        f"policy_network={p['sandbox_policy']['network_enabled']}"
    )

    # ---- APPROVAL (human decision) -------------------------------------
    approval = client.post(f"/api/findings/{fid}/approval")
    assert approval.status_code == 200
    a = approval.json()
    assert a["status"] == "pending"
    decided = client.post(
        f"/api/approvals/{a['id']}/approve",
        json={"reason": "controlled smoke decision"},
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    print(f"[llm-smoke] approval {a['id']} -> {decided.json()['status']}")
