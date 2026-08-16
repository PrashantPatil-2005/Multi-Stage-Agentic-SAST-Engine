"""Phase 14G tests: project-scoped findings + finding lineage enrichment.

Covers:
* GET /api/findings?project_id=<id> returns exactly the project's findings
  (resolved via the explicit scan lineage, never path guessing);
* unknown project -> 404 (no silent global fallback);
* GET /api/findings/{id} is enriched with the authoritative owning project
  and every producing scan run;
* two projects with identical code stay fully isolated in scoped reads;
* GET /api/scans lists recent runs (read-only);
* every read endpoint is a no-op on pipeline state;
* restart persistence of scoped lineage.
"""

from app.config import Settings
from app.main import create_app
from app.scan.run_store import get_scan_run_store
from app.validate.store import get_finding_store, get_validation_store
from fastapi.testclient import TestClient


def _settings(tmp_path, db_name: str = "lineage14g.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def _create_project(client: TestClient, fixture_repo, name: str) -> dict:
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


def test_project_scoped_findings_match_scan_lineage(client, fixture_repo):
    project = _create_project(client, fixture_repo, "scoped-app")
    scan = _scan(client, project["id"])
    assert scan["finding_ids"]

    scoped = client.get(f"/api/findings?project_id={project['id']}")
    assert scoped.status_code == 200
    body = scoped.json()
    assert {row["finding_id"] for row in body} == set(scan["finding_ids"])

    # global list is a superset of the scoped list
    global_ids = {row["finding_id"] for row in client.get("/api/findings").json()}
    assert set(scan["finding_ids"]) <= global_ids


def test_project_scoped_findings_unknown_project_404(client, fixture_repo):
    _create_project(client, fixture_repo, "other-app")
    resp = client.get("/api/findings?project_id=does-not-exist")
    assert resp.status_code == 404
    assert "project not found" in resp.json()["detail"]


def test_project_scoped_findings_empty_but_valid_zero(client, fixture_repo, tmp_path):
    """A registered project that was never scanned is an honest empty list
    (200 with []) - not a 404 and not a global fallback."""
    project = _create_project(client, fixture_repo, "never-scanned")
    resp = client.get(f"/api/findings?project_id={project['id']}")
    assert resp.status_code == 200
    assert resp.json() == []


def test_two_projects_identical_code_scoped_isolation(client, fixture_repo):
    a = _create_project(client, fixture_repo, "app-a")
    b = _create_project(client, fixture_repo, "app-b")
    scan_a = _scan(client, a["id"])
    scan_b = _scan(client, b["id"])

    ids_a = {row["finding_id"] for row in client.get(f"/api/findings?project_id={a['id']}").json()}
    ids_b = {row["finding_id"] for row in client.get(f"/api/findings?project_id={b['id']}").json()}
    assert ids_a == set(scan_a["finding_ids"])
    assert ids_b == set(scan_b["finding_ids"])
    assert ids_a.isdisjoint(ids_b)


def test_finding_detail_repository_and_scan_runs_from_lineage(client, fixture_repo):
    project = _create_project(client, fixture_repo, "lineage-app")
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]

    body = client.get(f"/api/findings/{finding_id}").json()
    assert body["project"] == {
        "project_id": project["id"],
        "name": "lineage-app",
        "source_type": "directory",
        "location": str(fixture_repo),
        "language": "python",
    }
    assert len(body["scan_runs"]) == 1
    run = body["scan_runs"][0]
    assert run["scan_run_id"] == scan["scan_run_id"]
    assert run["project_id"] == project["id"]
    assert run["status"] == "completed"
    assert run["total_findings"] == scan["total_findings"]


def test_finding_detail_scan_runs_list_all_observed_runs(client, fixture_repo):
    """Rescanning re-observes the same deterministic finding ids; the detail
    lists every producing run (newest first) instead of guessing one."""
    project = _create_project(client, fixture_repo, "rescan-app")
    first = _scan(client, project["id"])
    second = _scan(client, project["id"])
    assert sorted(first["finding_ids"]) == sorted(second["finding_ids"])
    finding_id = first["finding_ids"][0]

    body = client.get(f"/api/findings/{finding_id}").json()
    run_ids = [run["scan_run_id"] for run in body["scan_runs"]]
    assert run_ids == [second["scan_run_id"], first["scan_run_id"]]
    assert body["project"]["project_id"] == project["id"]


def test_finding_detail_lineage_unavailable_when_no_scan(client, fixture_repo):
    """A finding registered directly (no scan) has no lineage: project is
    None and scan_runs is empty - nothing is invented."""
    from tests.scan_test_helpers import scan_fixture_files

    report = scan_fixture_files("app.py")
    get_finding_store().add_report(report)
    finding_id = report.findings[0].id

    body = client.get(f"/api/findings/{finding_id}").json()
    assert body["project"] is None
    assert body["scan_runs"] == []


def test_recent_scans_endpoint(client, fixture_repo):
    project = _create_project(client, fixture_repo, "recent-app")
    first = _scan(client, project["id"])
    second = _scan(client, project["id"])

    resp = client.get("/api/scans?limit=5")
    assert resp.status_code == 200
    runs = resp.json()
    assert [run["scan_run_id"] for run in runs] == [
        second["scan_run_id"],
        first["scan_run_id"],
    ]
    assert all(run["project_id"] == project["id"] for run in runs)

    limited = client.get("/api/scans?limit=1").json()
    assert len(limited) == 1
    assert limited[0]["scan_run_id"] == second["scan_run_id"]


def test_read_endpoints_do_not_mutate_state(client, fixture_repo):
    project = _create_project(client, fixture_repo, "readonly-app")
    scan = _scan(client, project["id"])

    before = {
        "findings": len(client.get("/api/findings").json()),
        "validations": len(get_validation_store().all()),
    }

    client.get(f"/api/findings?project_id={project['id']}")
    client.get(f"/api/findings/{scan['finding_ids'][0]}")
    client.get(f"/api/scans/{scan['scan_run_id']}")
    client.get(f"/api/scans/{scan['scan_run_id']}/findings")
    client.get("/api/scans")

    after = {
        "findings": len(client.get("/api/findings").json()),
        "validations": len(get_validation_store().all()),
    }
    assert after == before
    assert len(get_scan_run_store().all_runs()) == 1


def test_restart_persistence_scoped_lineage(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        project = _create_project(client, fixture_repo, "persist-app")
        scan = _scan(client, project["id"])
        before = client.get(f"/api/findings?project_id={project['id']}").json()

    with _client(settings) as client:
        after = client.get(f"/api/findings?project_id={project['id']}").json()
        assert {row["finding_id"] for row in after} == {
            row["finding_id"] for row in before
        }
        detail = client.get(f"/api/findings/{before[0]['finding_id']}").json()
        assert detail["project"]["project_id"] == project["id"]
        assert detail["scan_runs"][0]["scan_run_id"] == scan["scan_run_id"]
