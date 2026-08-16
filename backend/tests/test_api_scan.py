"""API tests for the SCAN trigger endpoint.

POST /api/projects/{id}/scan runs the existing deterministic ScanService on
the prepared project's stored CodeModel and registers the findings in the
in-memory finding store (visible through the read-only /api/findings routes).
"""

import pytest

from app.validate.store import get_finding_store


@pytest.fixture(autouse=True)
def _clear_finding_store():
    get_finding_store().clear()
    yield
    get_finding_store().clear()


def _create_project(client, fixture_repo):
    resp = client.post(
        "/api/projects",
        json={
            "name": "scan-app",
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    )
    assert resp.status_code == 201
    return resp.json()


def test_scan_project_returns_report(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    resp = client.post(f"/api/projects/{project['id']}/scan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["project_id"] == project["id"]
    assert body["report_id"]
    assert body["created_at"]
    assert body["scanned_file_count"] >= 1
    assert body["total_findings"] > 0
    assert body["finding_ids"]
    assert set(body["by_type"]) <= {"sql_injection", "command_injection", "ssrf"}
    assert len(body["finding_ids"]) == body["total_findings"]


def test_scan_findings_visible_in_findings_endpoint(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    scan = client.post(f"/api/projects/{project['id']}/scan").json()
    listed = client.get("/api/findings")
    assert listed.status_code == 200
    ids = {item["finding_id"] for item in listed.json()}
    assert set(scan["finding_ids"]) <= ids


def test_scan_is_deterministic_and_idempotent(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    first = client.post(f"/api/projects/{project['id']}/scan").json()
    second = client.post(f"/api/projects/{project['id']}/scan").json()
    assert sorted(first["finding_ids"]) == sorted(second["finding_ids"])
    assert first["by_type"] == second["by_type"]
    listed = client.get("/api/findings")
    ids = [item["finding_id"] for item in listed.json()]
    assert len(ids) == len(set(ids))
    assert set(first["finding_ids"]) <= set(ids)


def test_scan_unknown_project_404(client):
    resp = client.post("/api/projects/does-not-exist/scan")
    assert resp.status_code == 404
    assert "project not found" in resp.json()["detail"]


def test_two_projects_with_identical_code_do_not_collide(client, fixture_repo):
    """GAP-02 regression: project-scoped ids, so identical vulnerable code in
    two repositories never overwrites in the shared finding store."""
    first = client.post(
        "/api/projects",
        json={
            "name": "app-a",
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    ).json()
    second = client.post(
        "/api/projects",
        json={
            "name": "app-b",
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    ).json()
    scan_a = client.post(f"/api/projects/{first['id']}/scan").json()
    scan_b = client.post(f"/api/projects/{second['id']}/scan").json()
    ids_a = set(scan_a["finding_ids"])
    ids_b = set(scan_b["finding_ids"])
    assert ids_a
    assert scan_a["total_findings"] == len(ids_a)
    assert ids_a.isdisjoint(ids_b)

    listed = client.get("/api/findings").json()
    listed_ids = [item["finding_id"] for item in listed]
    assert len(listed_ids) == len(set(listed_ids))
    assert len(listed_ids) == len(ids_a) + len(ids_b)

    rescan_a = client.post(f"/api/projects/{first['id']}/scan").json()
    assert set(rescan_a["finding_ids"]) == ids_a


def test_scan_of_empty_project_returns_zero_findings(client, tmp_path):
    empty = tmp_path / "empty-repo"
    empty.mkdir()
    (empty / "readme.txt").write_text("no python here", encoding="utf-8")
    project = client.post(
        "/api/projects",
        json={
            "name": "empty-app",
            "source_type": "directory",
            "location": str(empty),
        },
    ).json()
    resp = client.post(f"/api/projects/{project['id']}/scan")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_findings"] == 0
    assert body["finding_ids"] == []
    assert body["by_type"] == {}