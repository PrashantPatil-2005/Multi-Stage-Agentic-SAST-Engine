"""API tests for the PREPARE stage endpoints."""

import zipfile


def _create_project(client, name, source_type, location):
    return client.post(
        "/api/projects",
        json={"name": name, "source_type": source_type, "location": str(location)},
    )


def test_create_project_from_directory(client, fixture_repo):
    resp = _create_project(client, "vuln-app", "directory", fixture_repo)
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"]
    assert body["status"] == "prepared"
    assert body["summary"]["python_files"] == 7
    assert body["summary"]["parse_failures"] == 1


def test_get_project_detail(client, fixture_repo):
    created = _create_project(client, "vuln-app", "directory", fixture_repo).json()
    resp = client.get(f"/api/projects/{created['id']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == created["id"]
    app_meta = next(f for f in body["files"] if f["path"] == "app.py")
    assert len(app_meta["sha256"]) == 64
    assert app_meta["functions"] >= 4
    assert app_meta["error"] is None
    bad = next(f for f in body["files"] if f["path"] == "bad_syntax.py")
    assert bad["error"] is not None
    assert bad["error"]["message"]


def test_create_project_from_zip(client, fixture_repo, tmp_path):
    zip_path = tmp_path / "app.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for py in fixture_repo.rglob("*.py"):
            if "__pycache__" in py.parts or ".venv" in py.parts:
                continue
            zf.write(py, py.relative_to(fixture_repo).as_posix())
    resp = _create_project(client, "vuln-app-zip", "zip", zip_path)
    assert resp.status_code == 201
    assert resp.json()["summary"]["python_files"] == 7


def test_create_project_missing_directory_returns_400(client, tmp_path):
    resp = _create_project(client, "missing", "directory", tmp_path / "nope")
    assert resp.status_code == 400


def test_create_project_missing_zip_returns_400(client, tmp_path):
    resp = _create_project(client, "missing-zip", "zip", tmp_path / "nope.zip")
    assert resp.status_code == 400


def test_create_project_zip_traversal_returns_400(client, tmp_path):
    import stat as _stat

    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        info = zipfile.ZipInfo("../escape.py")
        zf.writestr(info, "print('pwn')\n")
    resp = _create_project(client, "evil", "zip", zip_path)
    assert resp.status_code == 400
    assert "security" in resp.json()["detail"].lower()


def test_create_project_invalid_source_type_returns_422(client):
    resp = client.post(
        "/api/projects",
        json={"name": "x", "source_type": "http", "location": "y"},
    )
    assert resp.status_code == 422


def test_get_missing_project_returns_404(client):
    resp = client.get("/api/projects/does-not-exist")
    assert resp.status_code == 404


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"