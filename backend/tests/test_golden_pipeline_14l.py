"""Phase 14L — golden end-to-end pipeline audit tests.

One fixture repository flows through the REAL API from PREPARE to APPROVAL,
with every stage explicitly executed against a single ``scan_run_id``. The
final ScanRun detail must show truthful, append-only execution history for
every applicable stage — nothing is fabricated and nothing is automatic.

Also covers (per the 14L audit spec):

* no automatic chaining: each stage is only ever executed by an explicit
  API action carrying its own ``scan_run_id`` context;
* cross-run isolation: Project A (runs A1, A2) and Project B (run B1) with
  the same fixture — project-scoped finding ids, independent stage state,
  cross-project / unknown run rejection;
* restart persistence: the full golden workflow survives a backend restart
  against the same SQLite file — no stage needs to be re-run;
* failure + retry: for every explicit-execution stage (DEDUPLICATE, RISK,
  SLA, VALIDATE, PROVE, APPROVAL) a forced failure records execution #1 as
  ``failed``; a retry records execution #2 as ``completed`` with
  ``execution_count == 2`` and the failed attempt still visible;
* approval semantics: request failure (gate), invalid transition and
  terminal rejection are never misclassified as successful executions.

The VALIDATE dependency is overridden with the deterministic fake LLM
provider (true_positive). PROVE runs the REAL approved sandbox harness
(in-memory SQLite fixture, no network) exactly like the pre-14K e2e test.
"""

import pytest

from app.api.routes.validations import get_validation_service
from app.approval.store import get_approval_store
from app.config import Settings
from app.dedup.service import reset_groups
from app.main import create_app
from app.risk.service import reset_risk_stores
from app.scan.run_store import get_scan_run_store
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from fastapi.testclient import TestClient
from tests.fake_llm_provider import FakeLLMProvider


@pytest.fixture(autouse=True)
def _clear_stores():
    stores = (
        get_finding_store,
        get_validation_store,
        get_approval_store,
        get_scan_run_store,
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
def validated_client(client):
    """Full API client whose VALIDATE dependency uses the fake LLM provider."""
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
    )
    yield client
    app.dependency_overrides.clear()


def _settings(tmp_path, db_name: str = "golden-14l.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def _create_project(client: TestClient, fixture_repo, name: str = "golden-app"):
    resp = client.post(
        "/api/projects",
        json={
            "name": name,
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    )
    assert resp.status_code == 201
    project = resp.json()
    assert project["status"] == "prepared"
    return project


def _scan(client: TestClient, project_id: str) -> dict:
    resp = client.post(f"/api/projects/{project_id}/scan")
    assert resp.status_code == 200
    return resp.json()


def _run_detail(client: TestClient, scan_run_id: str) -> dict:
    resp = client.get(f"/api/scans/{scan_run_id}")
    assert resp.status_code == 200
    return resp.json()


def _stages(client: TestClient, scan_run_id: str) -> dict:
    body = _run_detail(client, scan_run_id)
    return {stage["stage_name"]: stage for stage in body["stages"]}


def _executions_for(client: TestClient, scan_run_id: str, stage: str) -> list[dict]:
    body = _run_detail(client, scan_run_id)
    return [e for e in body["executions"] if e["stage_name"] == stage]


def _validate_and_prove(client: TestClient, finding_id: str, run_id: str):
    """VALIDATE + PROVE a finding against one explicit run (both completed)."""
    resp = client.post(
        f"/api/findings/{finding_id}/validate",
        json={"provider": "huggingface", "scan_run_id": run_id},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "true_positive"
    resp = client.post(f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"


# ======================================================================
# 3. GOLDEN END-TO-END FLOW
# ======================================================================

def test_golden_pipeline_all_stages_truthful(validated_client, fixture_repo):
    """The complete user journey through the real API, one explicit scan run.

    Final expected state (each stage completed by its own explicit action):
        PREPARE completed, SCAN completed, DEDUPLICATE completed,
        RISK completed, SLA completed, VALIDATE completed, PROVE completed,
        APPROVAL completed.
    """
    client = validated_client

    # ---- 1+2. CREATE REPOSITORY (PREPARE) ------------------------------
    project = _create_project(client, fixture_repo)
    # PREPARE does NOT automatically scan: no run exists yet.
    history = client.get(f"/api/projects/{project['id']}/scans").json()
    assert history == []

    # ---- 3+4. SCAN -> obtain scan_run_id --------------------------------
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    assert run_id
    assert scan["total_findings"] > 0
    assert scan["finding_ids"]

    # ---- 5. VERIFY SCAN EXECUTION (and no auto chaining) ----------------
    stages = _stages(client, run_id)
    assert stages["PREPARE"]["status"] == "completed"
    assert stages["PREPARE"]["execution_count"] == 1
    assert stages["SCAN"]["status"] == "completed"
    assert stages["SCAN"]["execution_count"] == 1
    for name in ("DEDUPLICATE", "RISK", "SLA", "VALIDATE", "PROVE", "APPROVAL"):
        assert stages[name]["status"] == "pending"
        assert stages[name]["execution_count"] == 0
    assert len(_executions_for(client, run_id, "SCAN")) == 1

    # ---- 6. OBTAIN FINDINGS FROM THAT SCAN RUN --------------------------
    resp = client.get(f"/api/scans/{run_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert {f["id"] for f in findings} == set(scan["finding_ids"])
    sql = next(f for f in findings if f["vulnerability_type"] == "sql_injection")
    fid = sql["id"]

    # ---- 7. DEDUPLICATE using scan_run_id -------------------------------
    resp = client.post(
        "/api/deduplicate",
        json={"finding_ids": scan["finding_ids"], "scan_run_id": run_id},
    )
    assert resp.status_code == 200
    stages = _stages(client, run_id)
    assert stages["DEDUPLICATE"]["status"] == "completed"
    assert stages["DEDUPLICATE"]["execution_count"] == 1
    # SCAN does NOT automatically deduplicate: exactly one DEDUPLICATE execution.
    assert len(_executions_for(client, run_id, "DEDUPLICATE")) == 1
    # DEDUP does NOT automatically risk.
    assert stages["RISK"]["status"] == "pending"

    # ---- 8. ASSESS RISK using scan_run_id -------------------------------
    resp = client.post(f"/api/findings/{fid}/risk", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["finding_id"] == fid
    stages = _stages(client, run_id)
    assert stages["RISK"]["status"] == "completed"
    assert stages["RISK"]["execution_count"] == 1
    # RISK does NOT automatically start SLA.
    assert stages["SLA"]["status"] == "pending"

    # ---- 9+10. START + CHECK SLA using scan_run_id ----------------------
    resp = client.post(f"/api/findings/{fid}/sla", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] in {"active", "not_applicable"}
    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "completed"
    assert stages["SLA"]["execution_count"] == 1

    resp = client.post(
        f"/api/findings/{fid}/sla/check", json={"scan_run_id": run_id}
    )
    assert resp.status_code == 200
    assert "sla" in resp.json()
    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "completed"
    assert stages["SLA"]["execution_count"] == 2
    assert len(_executions_for(client, run_id, "SLA")) == 2
    # SLA does NOT automatically validate.
    assert stages["VALIDATE"]["status"] == "pending"

    # ---- 11. VALIDATE using scan_run_id ---------------------------------
    resp = client.post(
        f"/api/findings/{fid}/validate",
        json={"provider": "huggingface", "scan_run_id": run_id},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "true_positive"
    stages = _stages(client, run_id)
    assert stages["VALIDATE"]["status"] == "completed"
    assert stages["VALIDATE"]["execution_count"] == 1
    # VALIDATE does NOT automatically prove.
    assert stages["PROVE"]["status"] == "pending"

    # ---- 12. PROVE using scan_run_id (real sandbox) ----------------------
    resp = client.post(f"/api/findings/{fid}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"
    stages = _stages(client, run_id)
    assert stages["PROVE"]["status"] == "completed"
    assert stages["PROVE"]["execution_count"] == 1
    # PROVE does NOT automatically request approval.
    assert stages["APPROVAL"]["status"] == "pending"

    # ---- 13. REQUEST APPROVAL using scan_run_id --------------------------
    resp = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    )
    assert resp.status_code == 200
    approval = resp.json()
    assert approval["status"] == "pending"
    assert approval["scan_run_id"] == run_id
    approval_id = approval["id"]
    stages = _stages(client, run_id)
    assert stages["APPROVAL"]["status"] == "completed"
    assert stages["APPROVAL"]["execution_count"] == 1

    # ---- 14. APPROVE the approval request --------------------------------
    decided = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "security-analyst", "reason": "golden flow decision"},
    )
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    # APPROVAL does NOT execute remediation: only the approval state changed.
    assert decided.json()["action"] == "remediation"
    assert decided.json()["status"] == "approved"

    # ---- 15. READ SCAN RUN DETAIL (truthful execution history) ------------
    body = _run_detail(client, run_id)
    assert body["run"]["scan_run_id"] == run_id
    assert body["run"]["status"] == "completed"
    assert body["run"]["error"] is None
    assert body["run"]["scanned_file_count"] == scan["scanned_file_count"]
    assert body["run"]["total_findings"] == scan["total_findings"]

    stages = {s["stage_name"]: s for s in body["stages"]}
    expected = {
        "PREPARE": 1,
        "SCAN": 1,
        "DEDUPLICATE": 1,
        "RISK": 1,
        "SLA": 2,  # start + check
        "VALIDATE": 1,
        "PROVE": 1,
        "APPROVAL": 2,  # request + approve
    }
    for name, count in expected.items():
        stage = stages[name]
        assert stage["status"] == "completed", f"{name} should be completed"
        assert stage["execution_count"] == count, f"{name} execution count"
        assert stage["error"] is None, f"{name} should have no error"
        assert stage["started_at"] is not None
        assert stage["completed_at"] is not None
        assert stage["completed_at"] >= stage["started_at"]

    executions = body["executions"]
    for name, count in expected.items():
        stage_executions = [e for e in executions if e["stage_name"] == name]
        assert len(stage_executions) == count, f"{name} execution history"
        assert all(e["status"] == "completed" for e in stage_executions)
        assert all(e["completed_at"] is not None for e in stage_executions)
        assert all(e["error"] is None for e in stage_executions)
        # append-only: distinct execution ids
        assert len({e["execution_id"] for e in stage_executions}) == count


# ======================================================================
# 5. CROSS-RUN ISOLATION
# ======================================================================

def test_cross_run_and_cross_project_isolation(validated_client, fixture_repo):
    """Project A (runs A1, A2) and Project B (run B1), same fixture.

    * finding ids are project-scoped (A and B are disjoint);
    * A1 and A2 share deterministic finding ids but keep independent stage
      state;
    * RISK / VALIDATE / PROVE / APPROVAL against A2 never touch A1;
    * a Project-A finding with a Project-B run is rejected (400);
    * unknown run ids are 404.
    """
    client = validated_client

    project_a = _create_project(client, fixture_repo, name="app-a")
    project_b = _create_project(client, fixture_repo, name="app-b")
    a1 = _scan(client, project_a["id"])
    a2 = _scan(client, project_a["id"])
    b1 = _scan(client, project_b["id"])

    # Project-scoped finding ids are isolated.
    ids_a1 = set(a1["finding_ids"])
    ids_a2 = set(a2["finding_ids"])
    ids_b1 = set(b1["finding_ids"])
    assert ids_a1
    assert ids_a1 == ids_a2  # deterministic ids repeat across rescans
    assert ids_a1.isdisjoint(ids_b1)

    # Distinct runs.
    assert a1["scan_run_id"] != a2["scan_run_id"] != b1["scan_run_id"]

    fid = sorted(ids_a1)[0]

    # ---- RISK against A2 only ------------------------------------------
    assert (
        client.post(
            f"/api/findings/{fid}/risk", json={"scan_run_id": a2["scan_run_id"]}
        ).status_code
        == 200
    )
    a1_stages = _stages(client, a1["scan_run_id"])
    a2_stages = _stages(client, a2["scan_run_id"])
    assert a1_stages["RISK"]["status"] == "pending"
    assert a1_stages["RISK"]["execution_count"] == 0
    assert a2_stages["RISK"]["status"] == "completed"
    assert a2_stages["RISK"]["execution_count"] == 1

    # ---- VALIDATE against A2 only --------------------------------------
    assert (
        client.post(
            f"/api/findings/{fid}/validate",
            json={"provider": "huggingface", "scan_run_id": a2["scan_run_id"]},
        ).status_code
        == 200
    )
    a1_stages = _stages(client, a1["scan_run_id"])
    a2_stages = _stages(client, a2["scan_run_id"])
    assert a1_stages["VALIDATE"]["status"] == "pending"
    assert a2_stages["VALIDATE"]["status"] == "completed"

    # ---- PROVE against A2 only ------------------------------------------
    assert (
        client.post(
            f"/api/findings/{fid}/prove", json={"scan_run_id": a2["scan_run_id"]}
        ).status_code
        == 200
    )
    a1_stages = _stages(client, a1["scan_run_id"])
    a2_stages = _stages(client, a2["scan_run_id"])
    assert a1_stages["PROVE"]["status"] == "pending"
    assert a2_stages["PROVE"]["status"] == "completed"

    # ---- APPROVAL against A2 only (request + decision inherit A2) -------
    created = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": a2["scan_run_id"],
        },
    ).json()
    assert created["scan_run_id"] == a2["scan_run_id"]
    assert (
        client.post(
            f"/api/approvals/{created['id']}/approve",
            json={"reviewed_by": "security-analyst", "reason": "isolation test"},
        ).status_code
        == 200
    )
    a1_stages = _stages(client, a1["scan_run_id"])
    a2_stages = _stages(client, a2["scan_run_id"])
    assert a1_stages["APPROVAL"]["status"] == "pending"
    assert a1_stages["APPROVAL"]["execution_count"] == 0
    assert a2_stages["APPROVAL"]["execution_count"] == 2
    assert not _executions_for(client, a1["scan_run_id"], "APPROVAL")
    assert len(_executions_for(client, a2["scan_run_id"], "APPROVAL")) == 2

    # ---- Project-A finding + Project-B run: rejected for every stage ----
    for url, body in [
        ("/api/deduplicate", {"finding_ids": [fid], "scan_run_id": b1["scan_run_id"]}),
        (f"/api/findings/{fid}/risk", {"scan_run_id": b1["scan_run_id"]}),
        (f"/api/findings/{fid}/sla", {"scan_run_id": b1["scan_run_id"]}),
        (
            f"/api/findings/{fid}/validate",
            {"provider": "huggingface", "scan_run_id": b1["scan_run_id"]},
        ),
        (f"/api/findings/{fid}/prove", {"scan_run_id": b1["scan_run_id"]}),
        (
            f"/api/findings/{fid}/approval",
            {"action": "remediation", "requested_by": "system", "scan_run_id": b1["scan_run_id"]},
        ),
    ]:
        resp = client.post(url, json=body)
        assert resp.status_code == 400, f"{url} should be rejected"
        assert "does not produce" in resp.json()["detail"]

    # B's stages stayed untouched.
    b_stages = _stages(client, b1["scan_run_id"])
    for name in ("RISK", "SLA", "VALIDATE", "PROVE", "APPROVAL", "DEDUPLICATE"):
        assert b_stages[name]["status"] == "pending"
        assert b_stages[name]["execution_count"] == 0

    # ---- Unknown run ids are 404 ----------------------------------------
    for url, body in [
        (f"/api/findings/{fid}/risk", {"scan_run_id": "does-not-exist"}),
        (
            f"/api/findings/{fid}/validate",
            {"provider": "huggingface", "scan_run_id": "does-not-exist"},
        ),
        (f"/api/findings/{fid}/prove", {"scan_run_id": "does-not-exist"}),
        (
            f"/api/findings/{fid}/approval",
            {"action": "remediation", "requested_by": "system", "scan_run_id": "does-not-exist"},
        ),
    ]:
        resp = client.post(url, json=body)
        assert resp.status_code == 404, f"{url} should be 404"
        assert "scan run not found" in resp.json()["detail"]


# ======================================================================
# 6. RESTART PERSISTENCE (full golden workflow)
# ======================================================================

def test_full_golden_workflow_survives_restart(tmp_path, fixture_repo):
    """Complete golden workflow, full backend restart, nothing re-run.

    Repository, scan run, scan findings, stage statuses, execution counts,
    execution history, validation, proof, approval, approval history, SLA
    and escalation state must all survive.
    """
    settings = _settings(tmp_path, db_name="restart-golden.db")

    # ---- first application instance: run the complete workflow ----------
    with _client(settings) as client:
        app = client.app
        app.dependency_overrides[get_validation_service] = lambda: ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
        )
        project = _create_project(client, fixture_repo)
        scan = _scan(client, project["id"])
        run_id = scan["scan_run_id"]
        fid = scan["finding_ids"][0]

        assert (
            client.post(
                "/api/deduplicate",
                json={"finding_ids": scan["finding_ids"], "scan_run_id": run_id},
            ).status_code
            == 200
        )
        assert (
            client.post(f"/api/findings/{fid}/risk", json={"scan_run_id": run_id}).status_code
            == 200
        )
        assert (
            client.post(f"/api/findings/{fid}/sla", json={"scan_run_id": run_id}).status_code
            == 200
        )
        assert (
            client.post(
                f"/api/findings/{fid}/sla/check", json={"scan_run_id": run_id}
            ).status_code
            == 200
        )
        _validate_and_prove(client, fid, run_id)

        created = client.post(
            f"/api/findings/{fid}/approval",
            json={
                "action": "remediation",
                "requested_by": "system",
                "scan_run_id": run_id,
            },
        ).json()
        assert created["scan_run_id"] == run_id
        approval_id = created["id"]
        decided = client.post(
            f"/api/approvals/{approval_id}/approve",
            json={"reviewed_by": "security-analyst", "reason": "restart audit"},
        ).json()
        assert decided["status"] == "approved"

        # create an escalation: breach the SLA via an explicit future check
        sla_before = client.get(f"/api/findings/{fid}/sla").json()
        future = sla_before["due_at"].replace("Z", "+00:00")
        from datetime import datetime, timedelta

        due = datetime.fromisoformat(future) + timedelta(hours=1)
        breached = client.post(
            f"/api/findings/{fid}/sla/check",
            json={"scan_run_id": run_id, "now": due.isoformat()},
        ).json()
        assert breached["escalation"] is not None

        before = _run_detail(client, run_id)
        history_before = client.get(f"/api/approvals/{approval_id}/history").json()
        findings_before = client.get(f"/api/scans/{run_id}/findings").json()
        validation_before = client.get(f"/api/findings/{fid}/validation").json()
        proof_before = client.get(f"/api/findings/{fid}/proof").json()
        approval_before = client.get(f"/api/findings/{fid}/approval").json()
        sla_before = client.get(f"/api/findings/{fid}/sla").json()
        escalations_before = client.get(f"/api/findings/{fid}/escalations").json()
        assert len(escalations_before) == 1

    # ---- second application instance: same SQLite file, nothing re-run ----
    with _client(settings) as client:
        # repository exists
        project_after = client.get(f"/api/projects/{project['id']}")
        assert project_after.status_code == 200
        assert project_after.json()["name"] == project["name"]

        # scan run + stage statuses + execution counts + history survive
        after = _run_detail(client, run_id)
        assert after == before
        assert after["run"]["status"] == "completed"
        stages = {s["stage_name"]: s for s in after["stages"]}
        for name, count in {
            "PREPARE": 1,
            "SCAN": 1,
            "DEDUPLICATE": 1,
            "RISK": 1,
            "SLA": 3,  # start + check + breach check
            "VALIDATE": 1,
            "PROVE": 1,
            "APPROVAL": 2,
        }.items():
            assert stages[name]["status"] == "completed"
            assert stages[name]["execution_count"] == count
        assert len(after["executions"]) == len(before["executions"])

        # scan findings survive
        assert client.get(f"/api/scans/{run_id}/findings").json() == findings_before

        # validation / proof / approval / approval history / SLA / escalations
        assert client.get(f"/api/findings/{fid}/validation").json() == validation_before
        assert client.get(f"/api/findings/{fid}/proof").json() == proof_before
        assert client.get(f"/api/findings/{fid}/approval").json() == approval_before
        assert client.get(f"/api/approvals/{approval_id}/history").json() == history_before
        sla_after = client.get(f"/api/findings/{fid}/sla").json()
        assert sla_after["status"] == "breached"
        assert sla_after["escalation_level"] == 1
        assert client.get(f"/api/findings/{fid}/escalations").json() == escalations_before

        # the composed finding detail shows the surviving story
        detail = client.get(f"/api/findings/{fid}").json()
        assert detail["approval"]["status"] == "approved"
        assert detail["validation"]["verdict"] == "true_positive"
        assert detail["proof"]["status"] == "verified"


# ======================================================================
# 7. FAILURE + RETRY AUDIT
# ======================================================================

def test_dedup_failure_then_retry(client, fixture_repo, monkeypatch):
    """DEDUPLICATE: execution #1 failed -> retry #2 completed, count 2."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]

    def _boom(self, findings):
        raise RuntimeError("simulated dedup failure")

    monkeypatch.setattr("app.dedup.service.DeduplicationService.deduplicate", _boom)
    with pytest.raises(RuntimeError, match="simulated dedup failure"):
        client.post(
            "/api/deduplicate",
            json={"finding_ids": scan["finding_ids"], "scan_run_id": run_id},
        )
    monkeypatch.undo()

    stages = _stages(client, run_id)
    assert stages["DEDUPLICATE"]["status"] == "failed"
    assert stages["DEDUPLICATE"]["execution_count"] == 1
    executions = _executions_for(client, run_id, "DEDUPLICATE")
    assert len(executions) == 1
    assert executions[0]["status"] == "failed"
    assert executions[0]["error"] == "simulated dedup failure"

    resp = client.post(
        "/api/deduplicate",
        json={"finding_ids": scan["finding_ids"], "scan_run_id": run_id},
    )
    assert resp.status_code == 200
    stages = _stages(client, run_id)
    assert stages["DEDUPLICATE"]["status"] == "completed"
    assert stages["DEDUPLICATE"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "DEDUPLICATE")
    assert [e["status"] for e in executions] == ["failed", "completed"]
    assert executions[0]["error"] == "simulated dedup failure"
    assert executions[1]["error"] is None


def test_risk_failure_then_retry(client, fixture_repo, monkeypatch):
    """RISK: execution #1 failed -> retry #2 completed, count 2."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]

    def _boom(self, finding, validation, proof):
        raise RuntimeError("simulated risk failure")

    monkeypatch.setattr("app.risk.service.RiskService.assess", _boom)
    with pytest.raises(RuntimeError, match="simulated risk failure"):
        client.post(f"/api/findings/{fid}/risk", json={"scan_run_id": run_id})
    monkeypatch.undo()

    stages = _stages(client, run_id)
    assert stages["RISK"]["status"] == "failed"
    assert stages["RISK"]["execution_count"] == 1

    resp = client.post(f"/api/findings/{fid}/risk", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    stages = _stages(client, run_id)
    assert stages["RISK"]["status"] == "completed"
    assert stages["RISK"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "RISK")
    assert [e["status"] for e in executions] == ["failed", "completed"]
    assert executions[0]["error"] == "simulated risk failure"


def test_sla_failure_then_retry(client, fixture_repo, monkeypatch):
    """SLA: execution #1 failed -> retry #2 completed, count 2."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]

    assert client.post(f"/api/findings/{fid}/risk", json={"scan_run_id": run_id}).status_code == 200

    def _boom(self, assessment, started_at=None):
        raise RuntimeError("simulated sla failure")

    monkeypatch.setattr("app.risk.service.SLAService.create_sla", _boom)
    with pytest.raises(RuntimeError, match="simulated sla failure"):
        client.post(f"/api/findings/{fid}/sla", json={"scan_run_id": run_id})
    monkeypatch.undo()

    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "failed"
    assert stages["SLA"]["execution_count"] == 1

    resp = client.post(f"/api/findings/{fid}/sla", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "completed"
    assert stages["SLA"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "SLA")
    assert [e["status"] for e in executions] == ["failed", "completed"]
    assert executions[0]["error"] == "simulated sla failure"


def test_validate_failure_then_retry(validated_client, fixture_repo, monkeypatch):
    """VALIDATE: provider failure (503) -> failed; retry -> completed, count 2."""
    from app.validate.providers.base import ConfigurationError

    client = validated_client
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]

    def _boom(self, finding, *, sources=None, provider=None, provider_name=None):
        raise ConfigurationError("provider not configured")

    monkeypatch.setattr("app.validate.service.ValidationService.validate", _boom)
    resp = client.post(
        f"/api/findings/{fid}/validate",
        json={"provider": "huggingface", "scan_run_id": run_id},
    )
    assert resp.status_code == 503
    monkeypatch.undo()

    stages = _stages(client, run_id)
    assert stages["VALIDATE"]["status"] == "failed"
    assert stages["VALIDATE"]["execution_count"] == 1
    assert "provider not configured" in stages["VALIDATE"]["error"]

    resp = client.post(
        f"/api/findings/{fid}/validate",
        json={"provider": "huggingface", "scan_run_id": run_id},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "true_positive"
    stages = _stages(client, run_id)
    assert stages["VALIDATE"]["status"] == "completed"
    assert stages["VALIDATE"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "VALIDATE")
    assert [e["status"] for e in executions] == ["failed", "completed"]
    assert executions[0]["error"] == "provider not configured"


def test_prove_failure_then_retry(validated_client, fixture_repo, monkeypatch):
    """PROVE: harness exception -> failed; retry -> completed, count 2."""
    from app.prove.service import ProofService

    client = validated_client
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]
    _validate_and_prove(client, fid, run_id)

    # reset the PROVE stage so the failure below is a fresh execution
    # (the append-only history keeps the first completed execution)
    def _boom(self, finding, validation_result):
        raise RuntimeError("simulated prove crash")

    monkeypatch.setattr(ProofService, "prove", _boom)
    with pytest.raises(RuntimeError, match="simulated prove crash"):
        client.post(f"/api/findings/{fid}/prove", json={"scan_run_id": run_id})
    monkeypatch.undo()

    stages = _stages(client, run_id)
    assert stages["PROVE"]["status"] == "failed"
    assert stages["PROVE"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "PROVE")
    assert [e["status"] for e in executions] == ["completed", "failed"]

    resp = client.post(f"/api/findings/{fid}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"
    stages = _stages(client, run_id)
    assert stages["PROVE"]["status"] == "completed"
    assert stages["PROVE"]["execution_count"] == 3
    executions = _executions_for(client, run_id, "PROVE")
    assert [e["status"] for e in executions] == ["completed", "failed", "completed"]


def test_approval_request_failure_then_retry(validated_client, fixture_repo):
    """APPROVAL request: gate rejection (409) -> failed; retry -> completed.

    A backend policy rejection (finding not validated/proven yet) is a
    FAILED execution — never a fabricated success.
    """
    client = validated_client
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]

    # request without VALIDATE/PROVE -> eligibility gate rejects
    resp = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    )
    assert resp.status_code == 409
    assert "not eligible" in resp.json()["detail"] or "not been" in resp.json()["detail"]

    stages = _stages(client, run_id)
    assert stages["APPROVAL"]["status"] == "failed"
    assert stages["APPROVAL"]["execution_count"] == 1
    executions = _executions_for(client, run_id, "APPROVAL")
    assert len(executions) == 1
    assert executions[0]["status"] == "failed"
    assert "not been validated" in executions[0]["error"] or "not been proven" in executions[0]["error"]

    # now become eligible, retry -> completed, count 2
    _validate_and_prove(client, fid, run_id)
    resp = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending"
    stages = _stages(client, run_id)
    assert stages["APPROVAL"]["status"] == "completed"
    assert stages["APPROVAL"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "APPROVAL")
    assert [e["status"] for e in executions] == ["failed", "completed"]


def test_approval_terminal_states_are_truthful(validated_client, fixture_repo):
    """APPROVAL: invalid transition -> failed; terminal rejection is a
    successful transition (completed), never misclassified."""
    client = validated_client
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]
    _validate_and_prove(client, fid, run_id)

    created = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    ).json()
    approval_id = created["id"]

    # invalid transition: approving an already-approved request -> 409 failed
    assert (
        client.post(
            f"/api/approvals/{approval_id}/approve",
            json={"reviewed_by": "security-analyst"},
        ).status_code
        == 200
    )
    resp = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "security-analyst"},
    )
    assert resp.status_code == 409
    assert "invalid approval transition" in resp.json()["detail"]
    stages = _stages(client, run_id)
    assert stages["APPROVAL"]["status"] == "failed"
    assert stages["APPROVAL"]["execution_count"] == 3
    executions = _executions_for(client, run_id, "APPROVAL")
    assert [e["status"] for e in executions] == ["completed", "completed", "failed"]
    # the underlying state machine is untouched: still approved, version 1
    stored = get_approval_store().get(approval_id)
    assert stored.status == "approved"
    assert stored.version == 1


def test_approval_rejection_is_completed_transition(validated_client, fixture_repo):
    """A terminal REJECT is a successful transition (completed execution)."""
    client = validated_client
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    run_id = scan["scan_run_id"]
    fid = scan["finding_ids"][0]
    _validate_and_prove(client, fid, run_id)

    created = client.post(
        f"/api/findings/{fid}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    ).json()
    resp = client.post(
        f"/api/approvals/{created['id']}/reject",
        json={"reviewed_by": "security-analyst", "reason": "not acceptable"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"
    stages = _stages(client, run_id)
    assert stages["APPROVAL"]["status"] == "completed"
    assert stages["APPROVAL"]["execution_count"] == 2
    executions = _executions_for(client, run_id, "APPROVAL")
    assert [e["status"] for e in executions] == ["completed", "completed"]
