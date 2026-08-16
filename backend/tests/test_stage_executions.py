"""Phase 14J tests: explicit per-stage execution recording against scan runs.

Covers:
* SCAN stays completed (one recorded execution) after the initial scan;
* DEDUPLICATE / RISK / SLA executions update the correct scan run when a
  ``scan_run_id`` context is supplied, and stay ``pending`` otherwise;
* failed stages become ``failed`` with real timestamps + persisted error;
* retrying a failed stage preserves history (append-only executions);
* same finding observed by two scan runs keeps independent stage state;
* cross-project and unknown ``scan_run_id`` contexts are rejected;
* existing clients without ``scan_run_id`` still work (no stage record);
* the background SLA evaluator never marks a scan-run stage as executed;
* no automatic downstream stages are triggered;
* stage state + execution history survive backend restart.
"""

from datetime import timedelta

import pytest

from app.config import Settings
from app.main import create_app
from app.risk.sla_evaluator import SlaEvaluator
from app.risk.service import get_sla_record, reset_risk_stores
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _clear_stores():
    get_finding_store().clear()
    get_scan_run_store().clear()
    reset_risk_stores()
    yield
    get_finding_store().clear()
    get_scan_run_store().clear()
    reset_risk_stores()


def _settings(tmp_path, db_name: str = "stage-executions.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def _create_project(client: TestClient, fixture_repo, name: str = "stage-app"):
    project = client.post(
        "/api/projects",
        json={
            "name": name,
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    ).json()
    assert project["status"] == "prepared"
    return project


def _scan(client: TestClient, project_id: str) -> dict:
    resp = client.post(f"/api/projects/{project_id}/scan")
    assert resp.status_code == 200
    return resp.json()


def _stages(client: TestClient, scan_run_id: str) -> dict:
    body = client.get(f"/api/scans/{scan_run_id}").json()
    return {stage["stage_name"]: stage for stage in body["stages"]}


def _executions(client: TestClient, scan_run_id: str) -> list[dict]:
    return client.get(f"/api/scans/{scan_run_id}").json()["executions"]


def _risk(client: TestClient, finding_id: str, scan_run_id: str | None = None):
    body = {"scan_run_id": scan_run_id} if scan_run_id else None
    return client.post(f"/api/findings/{finding_id}/risk", json=body)


def test_scan_stage_records_one_execution(client, fixture_repo):
    """TEST 1: SCAN stays completed and records exactly one execution."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])

    stages = _stages(client, scan["scan_run_id"])
    assert stages["SCAN"]["status"] == "completed"
    assert stages["SCAN"]["execution_count"] == 1
    assert stages["SCAN"]["last_execution_at"]

    executions = _executions(client, scan["scan_run_id"])
    scan_executions = [e for e in executions if e["stage_name"] == "SCAN"]
    assert len(scan_executions) == 1
    execution = scan_executions[0]
    assert execution["status"] == "completed"
    assert execution["completed_at"] is not None
    assert execution["error"] is None
    # PREPARE is recorded as completed when the run is created.
    prepare_executions = [e for e in executions if e["stage_name"] == "PREPARE"]
    assert len(prepare_executions) == 1
    assert prepare_executions[0]["status"] == "completed"
    for name in ("DEDUPLICATE", "RISK", "SLA", "VALIDATE", "PROVE", "APPROVAL"):
        assert stages[name]["status"] == "pending"
        assert stages[name]["execution_count"] == 0


def test_dedup_execution_updates_the_correct_scan_run(client, fixture_repo):
    """TEST 2: DEDUPLICATE executes against the explicitly supplied run."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_ids = scan["finding_ids"]

    resp = client.post(
        "/api/deduplicate",
        json={"finding_ids": finding_ids, "scan_run_id": scan["scan_run_id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["total_findings"] == len(finding_ids)

    stages = _stages(client, scan["scan_run_id"])
    assert stages["DEDUPLICATE"]["status"] == "completed"
    assert stages["DEDUPLICATE"]["execution_count"] == 1
    assert stages["DEDUPLICATE"]["error"] is None
    # no automatic downstream stages
    assert stages["RISK"]["status"] == "pending"
    assert stages["SLA"]["status"] == "pending"
    # SCAN untouched
    assert stages["SCAN"]["execution_count"] == 1


def test_dedup_zero_findings_still_records_execution(client, fixture_repo):
    """Dedup with an empty finding list, actually executed, completes with 0."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])

    resp = client.post(
        "/api/deduplicate",
        json={"finding_ids": [], "scan_run_id": scan["scan_run_id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["total_findings"] == 0
    assert _stages(client, scan["scan_run_id"])["DEDUPLICATE"]["status"] == "completed"


def test_risk_execution_updates_the_correct_scan_run(client, fixture_repo):
    """TEST 3: RISK executes against the explicitly supplied run."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]

    resp = _risk(client, finding_id, scan["scan_run_id"])
    assert resp.status_code == 200
    assert resp.json()["finding_id"] == finding_id

    stages = _stages(client, scan["scan_run_id"])
    assert stages["RISK"]["status"] == "completed"
    assert stages["RISK"]["execution_count"] == 1
    assert stages["DEDUPLICATE"]["status"] == "pending"
    assert stages["SLA"]["status"] == "pending"
    assert stages["SCAN"]["execution_count"] == 1


def test_sla_execution_updates_the_correct_scan_run(client, fixture_repo):
    """TEST 4: SLA start and check both execute against the supplied run."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]
    run_id = scan["scan_run_id"]

    assert _risk(client, finding_id, run_id).status_code == 200
    start = client.post(f"/api/findings/{finding_id}/sla", json={"scan_run_id": run_id})
    assert start.status_code == 200
    assert start.json()["status"] == "active"

    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "completed"
    assert stages["SLA"]["execution_count"] == 1

    check = client.post(
        f"/api/findings/{finding_id}/sla/check", json={"scan_run_id": run_id}
    )
    assert check.status_code == 200
    stages = _stages(client, run_id)
    assert stages["SLA"]["execution_count"] == 2
    assert stages["SLA"]["status"] == "completed"
    sla_executions = [
        e for e in _executions(client, run_id) if e["stage_name"] == "SLA"
    ]
    assert len(sla_executions) == 2


def test_failed_stage_becomes_failed_with_error(client, fixture_repo, monkeypatch):
    """TEST 5: a failing stage marks the stage failed with a persisted error."""
    def _boom(self, finding, validation, proof):
        raise RuntimeError("simulated risk failure")

    monkeypatch.setattr("app.risk.service.RiskService.assess", _boom)

    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]

    with pytest.raises(RuntimeError, match="simulated risk failure"):
        _risk(client, finding_id, scan["scan_run_id"])

    stages = _stages(client, scan["scan_run_id"])
    risk_stage = stages["RISK"]
    assert risk_stage["status"] == "failed"
    assert risk_stage["error"] == "simulated risk failure"
    assert risk_stage["started_at"] is not None
    assert risk_stage["completed_at"] is not None
    assert risk_stage["completed_at"] >= risk_stage["started_at"]

    executions = _executions(client, scan["scan_run_id"])
    failed = [e for e in executions if e["stage_name"] == "RISK"]
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"
    assert failed[0]["error"] == "simulated risk failure"
    assert failed[0]["completed_at"] is not None


def test_retry_preserves_history(client, fixture_repo, monkeypatch):
    """TEST 6: retrying a failed stage appends a new execution; the stage
    recovers to completed while the failed attempt stays in history."""
    original = __import__("app.risk.service", fromlist=["RiskService"]).RiskService.assess

    def _boom(self, finding, validation, proof):
        raise RuntimeError("simulated risk failure")

    monkeypatch.setattr("app.risk.service.RiskService.assess", _boom)

    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]
    run_id = scan["scan_run_id"]

    with pytest.raises(RuntimeError, match="simulated risk failure"):
        _risk(client, finding_id, run_id)
    stages = _stages(client, run_id)
    assert stages["RISK"]["status"] == "failed"
    assert stages["RISK"]["execution_count"] == 1

    monkeypatch.setattr("app.risk.service.RiskService.assess", original)
    assert _risk(client, finding_id, run_id).status_code == 200

    stages = _stages(client, run_id)
    assert stages["RISK"]["status"] == "completed"
    assert stages["RISK"]["execution_count"] == 2
    assert stages["RISK"]["completed_at"] >= stages["RISK"]["started_at"]

    risk_executions = [
        e for e in _executions(client, run_id) if e["stage_name"] == "RISK"
    ]
    assert [e["status"] for e in risk_executions] == ["failed", "completed"]
    assert risk_executions[0]["execution_id"] != risk_executions[1]["execution_id"]


def test_same_finding_two_runs_independent_stage_state(client, fixture_repo):
    """TEST 9: same finding in two runs of one project keeps independent state."""
    project = _create_project(client, fixture_repo)
    first = _scan(client, project["id"])
    second = _scan(client, project["id"])
    finding_id = first["finding_ids"][0]

    # Executing RISK against the second run must not touch the first.
    assert _risk(client, finding_id, second["scan_run_id"]).status_code == 200

    first_stages = _stages(client, first["scan_run_id"])
    second_stages = _stages(client, second["scan_run_id"])
    assert first_stages["RISK"]["status"] == "pending"
    assert first_stages["RISK"]["execution_count"] == 0
    assert second_stages["RISK"]["status"] == "completed"
    assert second_stages["RISK"]["execution_count"] == 1
    assert not [
        e
        for e in _executions(client, first["scan_run_id"])
        if e["stage_name"] == "RISK"
    ]
    assert len(
        [
            e
            for e in _executions(client, second["scan_run_id"])
            if e["stage_name"] == "RISK"
        ]
    ) == 1


def test_cross_project_scan_run_rejected(client, fixture_repo):
    """TEST 10: a finding can never be attached to another project's run."""
    project_a = _create_project(client, fixture_repo, name="app-a")
    project_b = _create_project(client, fixture_repo, name="app-b")
    scan_a = _scan(client, project_a["id"])
    scan_b = _scan(client, project_b["id"])
    finding_a = scan_a["finding_ids"][0]
    finding_b = scan_b["finding_ids"][0]

    # finding from A + run from B -> 400, no stage record
    resp = _risk(client, finding_a, scan_b["scan_run_id"])
    assert resp.status_code == 400
    assert "does not produce finding" in resp.json()["detail"]
    assert _stages(client, scan_b["scan_run_id"])["RISK"]["status"] == "pending"

    # finding from B + run from B -> works
    assert _risk(client, finding_b, scan_b["scan_run_id"]).status_code == 200

    # dedup mixing finding A into run B -> 400
    dedup = client.post(
        "/api/deduplicate",
        json={"finding_ids": [finding_a], "scan_run_id": scan_b["scan_run_id"]},
    )
    assert dedup.status_code == 400
    assert _stages(client, scan_b["scan_run_id"])["DEDUPLICATE"]["status"] == "pending"


def test_unknown_scan_run_rejected(client, fixture_repo):
    """TEST 11: an unknown scan_run_id is a 404, never silently ignored."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]

    assert _risk(client, finding_id, "does-not-exist").status_code == 404
    dedup = client.post(
        "/api/deduplicate",
        json={"finding_ids": [finding_id], "scan_run_id": "does-not-exist"},
    )
    assert dedup.status_code == 404
    assert _stages(client, scan["scan_run_id"])["RISK"]["status"] == "pending"


def test_clients_without_scan_run_id_still_work(client, fixture_repo):
    """TEST 12: existing clients that omit scan_run_id run unchanged and
    never fabricate a stage record."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]

    resp = client.post(f"/api/findings/{finding_id}/risk")
    assert resp.status_code == 200
    assert resp.json()["finding_id"] == finding_id

    stages = _stages(client, scan["scan_run_id"])
    assert stages["RISK"]["status"] == "pending"
    assert stages["RISK"]["execution_count"] == 0
    assert not [
        e for e in _executions(client, scan["scan_run_id"]) if e["stage_name"] == "RISK"
    ]

    sla = client.post(f"/api/findings/{finding_id}/sla")
    assert sla.status_code == 200
    assert _stages(client, scan["scan_run_id"])["SLA"]["status"] == "pending"

    dedup = client.post("/api/deduplicate", json={"finding_ids": scan["finding_ids"]})
    assert dedup.status_code == 200
    assert _stages(client, scan["scan_run_id"])["DEDUPLICATE"]["status"] == "pending"


def test_background_sla_evaluator_never_marks_stage(client, fixture_repo):
    """TEST 13: the background SLA evaluator updates SLA records only; it
    must not record a scan-run SLA stage execution."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]
    run_id = scan["scan_run_id"]

    # create SLA + record without a scan-run context (stage stays pending)
    assert _risk(client, finding_id, run_id).status_code == 200
    assert client.post(f"/api/findings/{finding_id}/sla").status_code == 200
    assert _stages(client, run_id)["SLA"]["status"] == "pending"

    record = get_sla_record(finding_id)
    assert record is not None and record.status == "active"

    stats = SlaEvaluator(interval_seconds=3600).evaluate_once(
        now=record.due_at + timedelta(hours=1)
    )
    assert stats.breached == 1
    assert get_sla_record(finding_id).status == "breached"

    stages = _stages(client, run_id)
    assert stages["SLA"]["status"] == "pending"
    assert stages["SLA"]["execution_count"] == 0
    assert not [e for e in _executions(client, run_id) if e["stage_name"] == "SLA"]


def test_restart_persistence_of_stage_state(tmp_path, fixture_repo):
    """TEST 8: stage status, timestamps, errors and execution history survive
    a backend restart."""
    settings = _settings(tmp_path)
    with _client(settings) as client:
        project = _create_project(client, fixture_repo)
        scan = _scan(client, project["id"])
        run_id = scan["scan_run_id"]
        finding_id = scan["finding_ids"][0]
        assert _risk(client, finding_id, run_id).status_code == 200
        assert _stages(client, run_id)["RISK"]["status"] == "completed"
        before = client.get(f"/api/scans/{run_id}").json()

    with _client(settings) as client:
        after = client.get(f"/api/scans/{run_id}").json()
        assert after == before
        stages = {s["stage_name"]: s for s in after["stages"]}
        assert stages["SCAN"]["status"] == "completed"
        assert stages["SCAN"]["execution_count"] == 1
        assert stages["RISK"]["status"] == "completed"
        assert stages["RISK"]["execution_count"] == 1
        assert stages["RISK"]["started_at"] == before["stages"][
            [s["stage_name"] for s in before["stages"]].index("RISK")
        ]["started_at"]
        assert stages["DEDUPLICATE"]["status"] == "pending"
        assert stages["SLA"]["status"] == "pending"
        risk_executions = [
            e for e in after["executions"] if e["stage_name"] == "RISK"
        ]
        assert len(risk_executions) == 1
        assert risk_executions[0]["status"] == "completed"
        assert risk_executions[0]["completed_at"] is not None


def test_restart_persistence_of_failed_stage(tmp_path, fixture_repo, monkeypatch):
    """Failed stage errors survive restart too."""
    def _boom(self, finding, validation, proof):
        raise RuntimeError("persisted risk failure")

    monkeypatch.setattr("app.risk.service.RiskService.assess", _boom)

    settings = _settings(tmp_path, db_name="failed-stage.db")
    with _client(settings) as client:
        project = _create_project(client, fixture_repo)
        scan = _scan(client, project["id"])
        run_id = scan["scan_run_id"]
        with pytest.raises(RuntimeError, match="persisted risk failure"):
            _risk(client, scan["finding_ids"][0], run_id)

    with _client(settings) as client:
        after = client.get(f"/api/scans/{run_id}").json()
        stages = {s["stage_name"]: s for s in after["stages"]}
        assert stages["RISK"]["status"] == "failed"
        assert stages["RISK"]["error"] == "persisted risk failure"
        assert stages["RISK"]["completed_at"] is not None
        risk_executions = [
            e for e in after["executions"] if e["stage_name"] == "RISK"
        ]
        assert risk_executions[0]["status"] == "failed"
        assert risk_executions[0]["error"] == "persisted risk failure"
