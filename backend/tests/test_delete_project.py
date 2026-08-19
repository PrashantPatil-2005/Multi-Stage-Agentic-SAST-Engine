"""Tests for repository deletion (DELETE /api/projects/{id}).

Deleting a repository must cascade over the persisted lineage
(project -> scan runs -> findings) and remove every pipeline record it
owns: findings, validation, proof, risk/SLA/escalation, approval requests
+ audit events, dedup group membership, scan runs (with stage/execution
history) and the prepared snapshot directory. Other projects are
untouched, unknown projects 404, and a project that was only prepared
(never scanned) is still fully removed.
"""

import pytest

from app.api.routes.validations import get_validation_service
from app.auth.seed import DEMO_PASSWORD
from app.config import Settings
from app.main import create_app
from app.validate.service import ValidationService
from fastapi.testclient import TestClient
from tests.fake_llm_provider import FakeLLMProvider


def _settings(tmp_path, db_name: str = "delete-project.db") -> Settings:
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


@pytest.fixture
def validated_client(client):
    """Client whose VALIDATE dependency returns a deterministic verdict."""
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
    )
    yield client
    app.dependency_overrides.clear()


def _create_project(client: TestClient, fixture_repo, name: str = "app"):
    resp = client.post(
        "/api/projects",
        json={"name": name, "source_type": "directory", "location": str(fixture_repo)},
    )
    assert resp.status_code == 201
    return resp.json()


def _scan(client: TestClient, project_id: str) -> dict:
    resp = client.post(f"/api/projects/{project_id}/scan")
    assert resp.status_code == 200
    return resp.json()


def _delete(client: TestClient, project_id: str):
    return client.delete(f"/api/projects/{project_id}")


def _stages(client: TestClient, run_id: str) -> dict:
    resp = client.get(f"/api/scans/{run_id}")
    assert resp.status_code == 200
    body = resp.json()
    return {s["stage_name"]: s for s in body["stages"]}


def test_delete_removes_project_and_every_pipeline_record(
    validated_client, fixture_repo, tmp_path
):
    """Full golden flow, then DELETE: nothing of that repository survives."""
    settings = _settings(tmp_path)
    with _client(settings) as client:
        app = client.app
        app.dependency_overrides[get_validation_service] = lambda: ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
        )
        project = _create_project(client, fixture_repo)
        scan = _scan(client, project["id"])
        run_id = scan["scan_run_id"]
        fid = scan["finding_ids"][0]

        # run the full pipeline so every store has a record to delete
        dedup = client.post(
            "/api/deduplicate",
            json={"finding_ids": scan["finding_ids"], "scan_run_id": run_id},
        )
        assert dedup.status_code == 200
        fingerprints = [g["fingerprint"] for g in dedup.json()["groups"]]
        assert fingerprints
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
                f"/api/findings/{fid}/validate",
                json={"provider": "huggingface", "scan_run_id": run_id},
            ).status_code
            == 200
        )
        assert (
            client.post(f"/api/findings/{fid}/prove", json={"scan_run_id": run_id}).status_code
            == 200
        )
        created = client.post(
            f"/api/findings/{fid}/approval",
            json={
                "action": "remediation",
                "requested_by": "manager",
                "scan_run_id": run_id,
            },
        ).json()
        assert (
            client.post(
                f"/api/approvals/{created['id']}/approve",
                json={"reviewed_by": "security-analyst", "reason": "delete audit"},
            ).status_code
            == 200
        )
        stages = _stages(client, run_id)
        assert stages["APPROVAL"]["execution_count"] == 2

        # dedup groups exist before deletion
        for fingerprint in fingerprints:
            assert client.get(f"/api/deduplication/{fingerprint}").status_code == 200
        resp = client.get("/api/repositories")
        assert resp.status_code == 200

        # ---- DELETE -------------------------------------------------------
        resp = _delete(client, project["id"])
        assert resp.status_code == 204

        # project row gone
        assert client.get(f"/api/projects/{project['id']}").status_code == 404
        # scan history gone
        assert client.get(f"/api/projects/{project['id']}/scans").status_code == 404
        assert client.get(f"/api/scans/{run_id}").status_code == 404
        assert client.get(f"/api/scans/{run_id}/findings").status_code == 404
        # finding + its pipeline records gone
        assert client.get(f"/api/findings/{fid}").status_code == 404
        assert client.get(f"/api/findings/{fid}/risk").status_code == 404
        assert client.get(f"/api/findings/{fid}/sla").status_code == 404
        assert client.get(f"/api/findings/{fid}/validation").status_code == 404
        assert client.get(f"/api/findings/{fid}/proof").status_code == 404
        assert client.get(f"/api/findings/{fid}/approval").status_code == 404
        assert client.get(f"/api/findings/{fid}/escalations").status_code == 404
        # the repository summary no longer lists the project
        repositories = client.get("/api/repositories").json()
        assert repositories["has_repositories"] is False
        assert repositories["repositories"] == []

        # dedup groups referencing the deleted findings are gone
        for fingerprint in fingerprints:
            assert client.get(f"/api/deduplication/{fingerprint}").status_code == 404

        # workspace directory removed
        workspace = settings.workspace_dir / "projects" / project["id"]
        assert not workspace.exists()


def test_delete_only_prepared_project(fixture_repo, tmp_path):
    """A project that was prepared but never scanned is still removed."""
    settings = _settings(tmp_path)
    with _client(settings) as client:
        project = _create_project(client, fixture_repo)
        assert _delete(client, project["id"]).status_code == 204
        assert client.get(f"/api/projects/{project['id']}").status_code == 404
        assert not (settings.workspace_dir / "projects" / project["id"]).exists()


def test_delete_unknown_project_returns_404(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        resp = _delete(client, "no-such-project")
        assert resp.status_code == 404
        assert "project not found" in resp.json()["detail"]


def test_delete_keeps_other_projects_isolated(validated_client, fixture_repo):
    """Deleting project A leaves project B's runs, findings and stages intact."""
    client = validated_client
    project_a = _create_project(client, fixture_repo, name="app-a")
    project_b = _create_project(client, fixture_repo, name="app-b")
    scan_a = _scan(client, project_a["id"])
    scan_b = _scan(client, project_b["id"])
    fid_b = scan_b["finding_ids"][0]

    # give B some stage state
    assert (
        client.post(
            f"/api/findings/{fid_b}/risk", json={"scan_run_id": scan_b["scan_run_id"]}
        ).status_code
        == 200
    )

    assert _delete(client, project_a["id"]).status_code == 204

    # A is gone
    assert client.get(f"/api/projects/{project_a['id']}").status_code == 404
    assert client.get(f"/api/scans/{scan_a['scan_run_id']}").status_code == 404
    assert client.get(f"/api/findings/{scan_a['finding_ids'][0]}").status_code == 404

    # B survives with all state
    assert client.get(f"/api/projects/{project_b['id']}").status_code == 200
    run_b = client.get(f"/api/scans/{scan_b['scan_run_id']}").json()
    assert run_b["run"]["status"] == "completed"
    stages_b = {s["stage_name"]: s for s in run_b["stages"]}
    assert stages_b["SCAN"]["status"] == "completed"
    assert stages_b["RISK"]["status"] == "completed"
    assert stages_b["RISK"]["execution_count"] == 1
    findings_b = client.get(f"/api/scans/{scan_b['scan_run_id']}/findings").json()
    assert {f["id"] for f in findings_b} == set(scan_b["finding_ids"])
    assert client.get(f"/api/findings/{fid_b}/risk").status_code == 200
