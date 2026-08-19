"""Persistence tests: pipeline state survives backend restart (Phase 14C).

Each test drives the real API against a file-backed SQLite database, then
recreates the application against the same database and asserts the
previously recorded state is served from the rehydrated stores — no stage
is re-run after the restart.
"""

from fastapi.testclient import TestClient

from app.api.routes.validations import get_validation_service
from app.auth.seed import DEMO_PASSWORD
from app.config import Settings
from app.db.session import init_db, make_engine, make_session_factory
from app.main import create_app
from app.validate.service import ValidationService
from tests.fake_llm_provider import FakeLLMProvider


def _settings(tmp_path, db_name: str = "persist.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings, fake_validation: bool = False) -> TestClient:
    app = create_app(settings)
    if fake_validation:
        app.dependency_overrides[get_validation_service] = lambda: ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
        )
    # Manually set up app state that the lifespan normally provides
    # (TestClient without 'with' does not trigger the lifespan)
    if not hasattr(app.state, "session_factory"):
        engine = make_engine(settings.database_url)
        init_db(engine)
        sf = make_session_factory(engine)
        app.state.settings = settings
        app.state.session_factory = sf
        app.state.prepare_service = None  # not needed for these tests
        # Seed demo users
        db = sf()
        try:
            from app.auth.seed import seed_demo_users
            seed_demo_users(db)
        finally:
            db.close()
    tc = TestClient(app)
    # Log in as manager (full permissions) for all API calls
    tc.post(
        "/api/auth/login",
        json={"username": "manager", "password": DEMO_PASSWORD},
    )
    return tc


def _create_and_scan(client: TestClient, fixture_repo, name: str = "persist-app"):
    project = client.post(
        "/api/projects",
        json={
            "name": name,
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    ).json()
    assert project["status"] == "prepared"
    scan = client.post(f"/api/projects/{project['id']}/scan").json()
    assert scan["finding_ids"]
    return project, scan


def _sql_finding_id(client: TestClient, scan: dict) -> str:
    listed = client.get("/api/findings").json()
    return next(
        item["finding_id"]
        for item in listed
        if item["vulnerability_type"] == "sql_injection"
    )


def test_finding_survives_restart(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        _, scan = _create_and_scan(client, fixture_repo)
        before = client.get(f"/api/findings/{scan['finding_ids'][0]}").json()
        assert before["finding_id"] == scan["finding_ids"][0]

    with _client(settings) as client:
        listed = client.get("/api/findings").json()
        assert {item["finding_id"] for item in listed} == set(scan["finding_ids"])
        restored = client.get(f"/api/findings/{scan['finding_ids'][0]}").json()
        assert restored == before
        assert restored["taint_path"] == before["taint_path"]


def test_downstream_state_survives_restart(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings, fake_validation=True) as client:
        _, scan = _create_and_scan(client, fixture_repo)
        fid = _sql_finding_id(client, scan)
        client.post("/api/deduplicate", json={"finding_ids": scan["finding_ids"]})
        validation = client.post(
            f"/api/findings/{fid}/validate", json={"provider": "huggingface"}
        ).json()
        assert validation["verdict"] == "true_positive"
        proof = client.post(f"/api/findings/{fid}/prove").json()
        assert proof["status"] == "verified"
        risk = client.post(f"/api/findings/{fid}/risk").json()
        sla = client.post(f"/api/findings/{fid}/sla").json()
        approval = client.post(f"/api/findings/{fid}/approval").json()
        decided = client.post(
            f"/api/approvals/{approval['id']}/approve",
            json={"reason": "decision survives restart"},
        ).json()
        assert decided["status"] == "approved"
        history = client.get(f"/api/approvals/{approval['id']}/history").json()

    with _client(settings) as client:
        assert client.get(f"/api/findings/{fid}/validation").json() == validation
        # GET /proof is a deliberately redacted view (no raw artifacts or
        # sandbox host paths); the POST /prove result is the full record.
        stored_proof = client.get(f"/api/findings/{fid}/proof").json()
        for key in ("status", "confidence", "summary", "duration_ms", "error"):
            assert stored_proof[key] == proof[key]
        assert stored_proof["sandbox_policy"]["network_enabled"] == \
            proof["sandbox_policy"]["network_enabled"]
        assert client.get(f"/api/findings/{fid}/risk").json() == risk
        assert client.get(f"/api/findings/{fid}/sla").json() == sla
        assert client.get(f"/api/findings/{fid}/approval").json() == decided
        assert client.get(f"/api/approvals/{approval['id']}/history").json() == history

        detail = client.get(f"/api/findings/{fid}").json()
        assert detail["validation"] == validation
        assert detail["proof"]["status"] == "verified"
        assert detail["approval"]["status"] == "approved"
        assert detail["approval"]["reviewed_by"] == "manager"
        assert detail["sla"]["priority"] == sla["priority"]

        listed = client.get("/api/findings").json()
        item = next(i for i in listed if i["finding_id"] == fid)
        assert item["verdict"] == "true_positive"
        assert item["proof_status"] == "verified"
        assert item["approval_status"] == "approved"
        assert item["priority"] == risk["priority"]

        summary = client.get("/api/risk/summary").json()
        assert any(row["finding_id"] == fid for row in summary["active_slas"])


def test_two_projects_identical_code_isolated_after_restart(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        _, scan_a = _create_and_scan(client, fixture_repo, name="app-a")
        _, scan_b = _create_and_scan(client, fixture_repo, name="app-b")
        assert set(scan_a["finding_ids"]).isdisjoint(set(scan_b["finding_ids"]))

    with _client(settings) as client:
        listed = client.get("/api/findings").json()
        ids = {item["finding_id"] for item in listed}
        assert set(scan_a["finding_ids"]) <= ids
        assert set(scan_b["finding_ids"]) <= ids
        assert len(ids) == len(scan_a["finding_ids"]) + len(scan_b["finding_ids"])


def test_dedup_groups_survive_restart(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        _, scan = _create_and_scan(client, fixture_repo)
        result = client.post(
            "/api/deduplicate", json={"finding_ids": scan["finding_ids"]}
        ).json()
        assert result["groups"]
        fingerprint = result["groups"][0]["fingerprint"]
        before = client.get(f"/api/deduplication/{fingerprint}").json()

    with _client(settings) as client:
        after = client.get(f"/api/deduplication/{fingerprint}").json()
        assert after["fingerprint"] == before["fingerprint"]
        assert after["canonical_finding_id"] == before["canonical_finding_id"]
        assert after["member_finding_ids"] == before["member_finding_ids"]
        assert after["occurrence_count"] == before["occurrence_count"]
        assert after["repositories"] == before["repositories"]
        assert after["representative_finding"]["id"] == before["representative_finding"]["id"]


def test_approval_history_survives_restart(tmp_path, fixture_repo):
    settings = _settings(tmp_path)
    with _client(settings, fake_validation=True) as client:
        _, scan = _create_and_scan(client, fixture_repo)
        fid = _sql_finding_id(client, scan)
        client.post(f"/api/findings/{fid}/validate", json={"provider": "huggingface"})
        client.post(f"/api/findings/{fid}/prove")
        approval = client.post(f"/api/findings/{fid}/approval").json()
        client.post(
            f"/api/approvals/{approval['id']}/request-changes",
            json={"reviewed_by": "reviewer-1", "reason": "fix the query first"},
        ).json()
        resubmitted = client.post(
            f"/api/approvals/{approval['id']}/resubmit",
            json={"reviewed_by": "reviewer-1", "reason": "fixed"},
        ).json()
        assert resubmitted["version"] == 2
        history = client.get(f"/api/approvals/{approval['id']}/history").json()
        assert len(history) == 3

    with _client(settings) as client:
        restored = client.get(f"/api/findings/{fid}/approval").json()
        assert restored == resubmitted
        assert restored["status"] == "pending"
        assert restored["version"] == 2
        history_restored = client.get(f"/api/approvals/{approval['id']}/history").json()
        assert history_restored == history
        assert [e["new_status"] for e in history_restored] == [
            "pending",
            "changes_requested",
            "pending",
        ]


def test_empty_database_behaves_like_fresh_application(tmp_path):
    settings = _settings(tmp_path)
    with _client(settings) as client:
        assert client.get("/api/findings").json() == []
        assert client.get("/api/approvals").json() == []
        assert client.get("/api/benchmarks").json() == {
            "has_reports": False,
            "reports": [],
        }
        assert client.get("/api/findings/does-not-exist").status_code == 404
        assert client.get("/api/risk/summary").status_code == 200


_LEGACY_DATETIME_TABLES = (
    "validation_results",
    "proof_results",
    "sla_records",
    "sla_events",
    "approval_requests",
    "approval_events",
    "scan_runs",
    "scan_stage_runs",
    "scan_stage_executions",
)


def _strip_utc_suffixes(db_path) -> None:
    """Rewrite persisted payloads so datetimes become naive (legacy rows).

    Older records stored datetimes without a UTC marker (e.g. from
    ``datetime.utcnow()``); on rehydration pydantic keeps them naive, and
    any read path that sorts/compares them against aware timestamps raises
    ``TypeError``. This helper reproduces that legacy state directly in the
    database so the regression test covers rehydrated, mixed-tz data.
    """
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        for table in _LEGACY_DATETIME_TABLES:
            rows = conn.execute(
                f"SELECT rowid, payload FROM {table}"
            ).fetchall()
            for rowid, payload in rows:
                if not payload or 'Z"' not in payload:
                    continue
                naive = payload.replace('Z"', '"')
                if naive != payload:
                    conn.execute(
                        f"UPDATE {table} SET payload = ? WHERE rowid = ?",
                        (naive, rowid),
                    )


def test_mixed_naive_datetimes_survive_restart(tmp_path, fixture_repo):
    """Read endpoints must not crash on legacy naive datetimes (regression).

    A pre-timezone-convention database holds naive ISO datetimes; after
    rehydration those mix with aware timestamps created by newer stages.
    Dashboard activity, approvals list/history, scan run detail, escalations
    and SLA checks all sort or compare datetimes, and previously raised
    ``TypeError`` (dashboard crashed 52x against the real database).
    """
    settings = _settings(tmp_path, db_name="legacy-tz.db")
    with _client(settings, fake_validation=True) as client:
        _, scan = _create_and_scan(client, fixture_repo)
        fid = _sql_finding_id(client, scan)
        client.post(f"/api/findings/{fid}/validate", json={"provider": "huggingface"})
        client.post(f"/api/findings/{fid}/prove")
        client.post(f"/api/findings/{fid}/risk")
        client.post(f"/api/findings/{fid}/sla")
        approval = client.post(f"/api/findings/{fid}/approval").json()
        client.post(
            f"/api/approvals/{approval['id']}/approve",
            json={"reviewed_by": "reviewer-1", "reason": "approved"},
        )

    _strip_utc_suffixes(tmp_path / "legacy-tz.db")

    with _client(settings) as client:
        run_id = scan["scan_run_id"]
        assert client.get("/api/dashboard/summary").status_code == 200
        assert client.get("/api/risk/summary").status_code == 200
        assert client.get("/api/approvals").status_code == 200
        assert client.get(f"/api/approvals/{approval['id']}/history").status_code == 200
        assert client.get(f"/api/scans/{run_id}").status_code == 200
        assert client.get(f"/api/findings/{fid}/escalations").status_code == 200
        assert client.post(f"/api/findings/{fid}/sla/check").status_code == 200

        dashboard = client.get("/api/dashboard/summary").json()
        assert dashboard["kpis"]["total_findings"]["value"] == len(
            scan["finding_ids"]
        )