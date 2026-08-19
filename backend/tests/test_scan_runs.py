"""Scan run lineage tests (Phase 14D).

Drives the real API: POST /api/projects/{id}/scan must produce a durable
ScanRun with stage + finding lineage, exposed through the new read-only
endpoints. Also covers controlled failure lineage and restart persistence.
"""

from datetime import datetime

import pytest

from app.auth.seed import DEMO_PASSWORD
from app.config import Settings
from app.main import create_app
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _clear_stores():
    get_finding_store().clear()
    get_scan_run_store().clear()
    yield
    get_finding_store().clear()
    get_scan_run_store().clear()


def _settings(tmp_path, db_name: str = "scanruns.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings) -> TestClient:
    app = create_app(settings)
    from app.db.session import init_db, make_engine, make_session_factory
    if not hasattr(app.state, "session_factory"):
        engine = make_engine(settings.database_url)
        init_db(engine)
        sf = make_session_factory(engine)
        app.state.settings = settings
        app.state.session_factory = sf
        app.state.prepare_service = None
        db = sf()
        try:
            from app.auth.seed import seed_demo_users
            seed_demo_users(db)
        finally:
            db.close()
    tc = TestClient(app)
    tc.post(
        "/api/auth/login",
        json={"username": "manager", "password": DEMO_PASSWORD},
    )
    return tc


def _create_project(client: TestClient, fixture_repo, name: str = "lineage-app"):
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


def test_scan_creates_scan_run(client, fixture_repo):
    """TEST 1: scan produces a completed run with real counts."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    assert scan["scan_run_id"]

    history = client.get(f"/api/projects/{project['id']}/scans")
    assert history.status_code == 200
    runs = history.json()
    assert len(runs) == 1
    run = runs[0]
    assert run["scan_run_id"] == scan["scan_run_id"]
    assert run["project_id"] == project["id"]
    assert run["status"] == "completed"
    assert run["started_at"]
    assert run["completed_at"]
    assert run["error"] is None
    assert run["scanned_file_count"] == scan["scanned_file_count"]
    assert run["total_findings"] == scan["total_findings"]
    assert datetime.fromisoformat(run["completed_at"]) >= datetime.fromisoformat(
        run["started_at"]
    )


def test_stage_lineage(client, fixture_repo):
    """TEST 2: SCAN completed; unexecuted stages never falsely completed."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])

    detail = client.get(f"/api/scans/{scan['scan_run_id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["run"]["scan_run_id"] == scan["scan_run_id"]
    stages = {stage["stage_name"]: stage for stage in body["stages"]}
    assert set(stages) == {
        "PREPARE",
        "SCAN",
        "DEDUPLICATE",
        "RISK",
        "SLA",
        "VALIDATE",
        "PROVE",
        "APPROVAL",
    }

    scan_stage = stages["SCAN"]
    assert scan_stage["status"] == "completed"
    assert scan_stage["started_at"]
    assert scan_stage["completed_at"]
    assert scan_stage["error"] is None

    prepare_stage = stages["PREPARE"]
    assert prepare_stage["status"] == "completed"
    assert prepare_stage["execution_count"] == 1
    assert prepare_stage["started_at"]
    assert prepare_stage["completed_at"]

    for name in ("DEDUPLICATE", "RISK", "SLA", "VALIDATE", "PROVE", "APPROVAL"):
        stage = stages[name]
        assert stage["status"] == "pending"
        assert stage["started_at"] is None
        assert stage["completed_at"] is None
        assert stage["error"] is None


def test_finding_lineage(client, fixture_repo):
    """TEST 3: scan findings are real findings, resolved from lineage."""
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])

    findings = client.get(f"/api/scans/{scan['scan_run_id']}/findings")
    assert findings.status_code == 200
    ids = [f["id"] for f in findings.json()]
    assert set(ids) == set(scan["finding_ids"])

    listed = client.get("/api/findings").json()
    listed_ids = {item["finding_id"] for item in listed}
    for finding_id in ids:
        assert finding_id in listed_ids


def test_multiple_scans_same_project(client, fixture_repo):
    """TEST 4: distinct run ids; deterministic finding ids may repeat
    without duplicating Finding records."""
    project = _create_project(client, fixture_repo)
    first = _scan(client, project["id"])
    second = _scan(client, project["id"])
    assert first["scan_run_id"] != second["scan_run_id"]

    history = client.get(f"/api/projects/{project['id']}/scans").json()
    assert {r["scan_run_id"] for r in history} == {
        first["scan_run_id"],
        second["scan_run_id"],
    }

    assert sorted(first["finding_ids"]) == sorted(second["finding_ids"])
    listed = client.get("/api/findings").json()
    listed_ids = [item["finding_id"] for item in listed]
    assert len(listed_ids) == len(set(listed_ids))

    first_findings = client.get(f"/api/scans/{first['scan_run_id']}/findings").json()
    second_findings = client.get(f"/api/scans/{second['scan_run_id']}/findings").json()
    assert {f["id"] for f in first_findings} == {f["id"] for f in second_findings}


def test_cross_project_lineage(client, fixture_repo):
    """TEST 5: separate projects never share scan runs or findings."""
    project_a = _create_project(client, fixture_repo, name="app-a")
    project_b = _create_project(client, fixture_repo, name="app-b")
    scan_a = _scan(client, project_a["id"])
    scan_b = _scan(client, project_b["id"])
    assert scan_a["scan_run_id"] != scan_b["scan_run_id"]

    history_a = client.get(f"/api/projects/{project_a['id']}/scans").json()
    history_b = client.get(f"/api/projects/{project_b['id']}/scans").json()
    assert {r["scan_run_id"] for r in history_a} == {scan_a["scan_run_id"]}
    assert {r["scan_run_id"] for r in history_b} == {scan_b["scan_run_id"]}
    assert all(r["project_id"] == project_a["id"] for r in history_a)
    assert all(r["project_id"] == project_b["id"] for r in history_b)

    findings_a = client.get(f"/api/scans/{scan_a['scan_run_id']}/findings").json()
    findings_b = client.get(f"/api/scans/{scan_b['scan_run_id']}/findings").json()
    assert {f["id"] for f in findings_a}.isdisjoint({f["id"] for f in findings_b})


def test_restart_persistence(tmp_path, fixture_repo):
    """TEST 6: scan history and stage records survive backend restart."""
    settings = _settings(tmp_path)
    with _client(settings) as client:
        project = _create_project(client, fixture_repo)
        scan = _scan(client, project["id"])
        before = client.get(f"/api/scans/{scan['scan_run_id']}").json()
        history_before = client.get(f"/api/projects/{project['id']}/scans").json()

    with _client(settings) as client:
        history_after = client.get(f"/api/projects/{project['id']}/scans").json()
        assert history_after == history_before
        after = client.get(f"/api/scans/{scan['scan_run_id']}").json()
        assert after == before
        assert after["run"]["status"] == "completed"
        assert {s["stage_name"] for s in after["stages"]} == {
            "PREPARE",
            "SCAN",
            "DEDUPLICATE",
            "RISK",
            "SLA",
            "VALIDATE",
            "PROVE",
            "APPROVAL",
        }


def test_failure_lineage(client, fixture_repo, monkeypatch):
    """TEST 7: a failing SCAN stage marks the run failed; later stages are
    never reported completed; the error is persisted; no fake counts."""

    def _boom(self, code_model, project_id=None):
        raise RuntimeError("simulated scanner failure")

    monkeypatch.setattr("app.scan.service.ScanService.scan", _boom)

    project = _create_project(client, fixture_repo)
    with pytest.raises(RuntimeError, match="simulated scanner failure"):
        client.post(f"/api/projects/{project['id']}/scan")

    history = client.get(f"/api/projects/{project['id']}/scans").json()
    assert len(history) == 1
    run = history[0]
    assert run["status"] == "failed"
    assert run["completed_at"]
    assert run["error"] == "simulated scanner failure"
    assert run["scanned_file_count"] is None
    assert run["total_findings"] is None

    detail = client.get(f"/api/scans/{run['scan_run_id']}").json()
    stages = {stage["stage_name"]: stage for stage in detail["stages"]}
    assert stages["SCAN"]["status"] == "failed"
    assert stages["SCAN"]["error"] == "simulated scanner failure"
    assert stages["SCAN"]["completed_at"]
    for name in ("DEDUPLICATE", "RISK", "SLA"):
        assert stages[name]["status"] == "pending"
        assert stages[name]["completed_at"] is None

    assert client.get(f"/api/scans/{run['scan_run_id']}/findings").json() == []
    assert client.get("/api/findings").json() == []


def test_scan_history_404s(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    assert client.get("/api/projects/does-not-exist/scans").status_code == 404
    assert client.get("/api/scans/does-not-exist").status_code == 404
    assert client.get("/api/scans/does-not-exist/findings").status_code == 404
    assert client.get(f"/api/scans/{scan['scan_run_id']}").status_code == 200