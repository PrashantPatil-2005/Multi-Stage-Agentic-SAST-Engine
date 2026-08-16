"""API tests for the SCAN trigger endpoint.

POST /api/projects/{id}/scan runs the existing deterministic ScanService on
the prepared project's stored CodeModel and registers the findings in the
in-memory finding store (visible through the read-only /api/findings routes).
"""


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