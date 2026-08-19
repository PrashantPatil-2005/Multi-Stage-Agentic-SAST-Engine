"""Remediation workflow API tests (post-approval, human-confirmed fixes).

Covers the full lifecycle: scan -> validate -> prove -> approve -> propose ->
apply (workspace copy only) -> re-prepare -> rescan -> verify, plus every
workflow gate (404/409) and the "no automatic fix" path (SSRF).
"""

import shutil
from pathlib import Path

import pytest

from app.approval.store import get_approval_store
from app.api.routes.validations import get_validation_service
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.remediation.store import get_remediation_store
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files

FIXTURE_SOURCE = (
    Path(__file__).parent / "fixtures" / "vulnerable_python_app" / "app.py"
)


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    get_remediation_store().clear()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    get_remediation_store().clear()


def _create_project(client, fixture_repo, name="remediation-app"):
    resp = client.post(
        "/api/projects",
        json={
            "name": name,
            "source_type": "directory",
            "location": str(fixture_repo),
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _scan_and_register(client, project_id):
    scan = client.post(f"/api/projects/{project_id}/scan")
    assert scan.status_code == 200
    body = scan.json()
    listed = client.get("/api/findings").json()
    by_type = {
        item["finding_id"]: item["vulnerability_type"] for item in listed
    }
    return body, by_type


def _validate_and_prove(client, finding_id):
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.94)
    )
    try:
        response = client.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "openai_compatible"},
        )
        assert response.status_code == 200
    finally:
        app.dependency_overrides.clear()
    proof = client.post(f"/api/findings/{finding_id}/prove")
    assert proof.status_code == 200
    assert proof.json()["status"] == "verified"


def _approve_remediation(client, finding_id):
    created = client.post(
        f"/api/findings/{finding_id}/approval",
        json={"action": "remediation", "requested_by": "manager"},
    )
    assert created.status_code == 200
    approval_id = created.json()["id"]
    approved = client.post(
        f"/api/approvals/{approval_id}/approve",
        json={"reviewed_by": "security-analyst", "reason": "Verified by proof."},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    return approval_id


def _finding_of_type(client, fixture_repo, vuln_type, sink_file=None):
    project = _create_project(client, fixture_repo)
    _, by_type = _scan_and_register(client, project["id"])
    candidates = [f for f, t in by_type.items() if t == vuln_type]
    if sink_file is not None:
        candidates = [
            f
            for f in candidates
            if get_finding_store().get(f).sink.file == sink_file
        ]
    finding_id = next(iter(candidates))
    _validate_and_prove(client, finding_id)
    _approve_remediation(client, finding_id)
    return project, finding_id


# --------------------------------------------------------------- routes


def test_remediation_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/findings/{finding_id}/remediation"]
    assert "post" in paths["/api/findings/{finding_id}/remediation/proposal"]
    assert "post" in paths["/api/findings/{finding_id}/remediation/apply"]
    assert "post" in paths["/api/findings/{finding_id}/remediation/verify"]
    assert "post" in paths["/api/projects/{project_id}/reprepare"]


# -------------------------------------------------------------- gates


def test_propose_without_approval_409(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    _, by_type = _scan_and_register(client, project["id"])
    finding_id = next(f for f, t in by_type.items() if t == "sql_injection")
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 409
    assert "approved approval" in response.json()["detail"]


def test_propose_with_pending_approval_409(client, fixture_repo):
    project, finding_id = _finding_of_type(client, fixture_repo, "sql_injection")
    get_approval_store().clear()
    created = client.post(f"/api/findings/{finding_id}/approval")
    assert created.status_code == 200
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 409
    assert "pending" in response.json()["detail"]


def test_propose_with_rejected_approval_409(client, fixture_repo):
    project, finding_id = _finding_of_type(client, fixture_repo, "sql_injection")
    get_approval_store().clear()
    approval_id = client.post(f"/api/findings/{finding_id}/approval").json()["id"]
    client.post(
        f"/api/approvals/{approval_id}/reject",
        json={"reviewed_by": "analyst", "reason": "risk accepted"},
    )
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 409


def test_propose_unknown_finding_404(client):
    response = client.post("/api/findings/does-not-exist/remediation/proposal")
    assert response.status_code == 404


def test_get_remediation_missing_404(client):
    response = client.get("/api/findings/does-not-exist/remediation")
    assert response.status_code == 404


def test_apply_without_proposal_409(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    response = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    assert response.status_code == 409
    assert "no remediation proposal" in response.json()["detail"]


# ------------------------------------------------------------- proposals


def test_propose_sql_injection_parameterizes_query(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 200
    record = response.json()
    assert record["finding_id"] == finding_id
    assert record["status"] == "proposed"
    proposal = record["proposal"]
    assert proposal["strategy"] == "parameterize_query"
    assert proposal["line"] == 15
    assert "?" in proposal["after"]
    assert "(user_id,)" in proposal["after"]
    assert proposal["before"] == "    cursor = conn.execute(query)"


def test_propose_ssrf_no_fix_available(client, fixture_repo):
    _, finding_id = _finding_of_type(client, fixture_repo, "ssrf")
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 200
    record = response.json()
    assert record["status"] == "no_fix_available"
    assert record["proposal"]["strategy"] == "no_automatic_fix"
    assert "manual" in record["proposal"]["rationale"]

    apply = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    assert apply.status_code == 409
    assert "manual" in apply.json()["detail"]


def test_propose_command_injection_shell_argument_vector(client, fixture_repo):
    _, finding_id = _finding_of_type(client, fixture_repo, "command_injection")
    response = client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert response.status_code == 200
    record = response.json()
    proposal = record["proposal"]
    assert proposal["strategy"] == "shell_argument_vector"
    assert proposal["after"] == "    subprocess.run(shlex.split(cmd))"
    assert proposal["import_to_add"] == "import shlex"


# ---------------------------------------------------------------- apply


def test_apply_requires_confirmation(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    response = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": False}
    )
    assert response.status_code == 409
    assert "confirmation" in response.json()["detail"]
    record = client.get(f"/api/findings/{finding_id}/remediation").json()
    assert record["status"] == "proposed"


def test_apply_missing_confirm_flag_422(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    response = client.post(f"/api/findings/{finding_id}/remediation/apply", json={})
    assert response.status_code == 422


def test_apply_patches_workspace_copy_only(client, fixture_repo):
    original_source = FIXTURE_SOURCE.read_text(encoding="utf-8")
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")

    response = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    assert response.status_code == 200
    record = response.json()
    assert record["status"] == "applied"
    assert record["applied_by"] == "security-analyst"
    assert record["applied_at"]

    # The original repository is never touched.
    assert FIXTURE_SOURCE.read_text(encoding="utf-8") == original_source

    # The workspace copy carries the patch.
    project_dir = client.app.state.settings.workspace_dir / "projects"
    repo_app = next(project_dir.glob("*/repo/app.py"))
    patched = repo_app.read_text(encoding="utf-8")
    assert "conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))" in patched
    assert "conn.execute(query)" not in patched


def test_apply_twice_409(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    first = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    assert first.status_code == 200
    second = client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    assert second.status_code == 409
    assert "already applied" in second.json()["detail"]


# ---------------------------------------------------------------- verify


def test_verify_requires_applied_fix_409(client, fixture_repo):
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    response = client.post(f"/api/findings/{finding_id}/remediation/verify")
    assert response.status_code == 409
    assert "applied" in response.json()["detail"]


def test_verify_before_reprepare_is_still_present(client, fixture_repo):
    """Verification re-scans the CURRENT snapshot; without re-prepare the old
    code model still produces the finding, so the result is honest."""
    _, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    response = client.post(f"/api/findings/{finding_id}/remediation/verify")
    assert response.status_code == 200
    assert response.json()["status"] == "still_present"


def test_full_remediation_lifecycle(client, fixture_repo):
    """TEST 11: the complete end-to-end remediation loop."""
    project = _create_project(client, fixture_repo)
    scan, by_type = _scan_and_register(client, project["id"])
    assert by_type  # the fixture is vulnerable
    sql_ids = [f for f, t in by_type.items() if t == "sql_injection"]
    app_sql_id = next(
        f for f in sql_ids if get_finding_store().get(f).sink.file == "app.py"
    )

    fixed_ids = []
    for finding_id in sql_ids:
        _validate_and_prove(client, finding_id)
        _approve_remediation(client, finding_id)
        proposal = client.post(f"/api/findings/{finding_id}/remediation/proposal")
        assert proposal.status_code == 200
        record = proposal.json()
        if record["status"] == "no_fix_available":
            continue  # e.g. db.py parameter sink: manual remediation required
        # Apply (explicit human confirmation)
        applied = client.post(
            f"/api/findings/{finding_id}/remediation/apply",
            json={"confirm": True},
        )
        assert applied.status_code == 200
        assert applied.json()["status"] == "applied"
        fixed_ids.append(finding_id)

    assert app_sql_id in fixed_ids

    # Re-prepare so the snapshot reflects the patched workspace copy.
    reprepared = client.post(f"/api/projects/{project['id']}/reprepare")
    assert reprepared.status_code == 200
    assert reprepared.json()["status"] == "prepared"

    # Rescan: every patched finding must be gone.
    rescan = client.post(f"/api/projects/{project['id']}/scan")
    assert rescan.status_code == 200
    new_ids = rescan.json()["finding_ids"]
    for finding_id in fixed_ids:
        assert finding_id not in new_ids

    # Verify: deterministic rescan says each patched finding is resolved.
    for finding_id in fixed_ids:
        verified = client.post(f"/api/findings/{finding_id}/remediation/verify")
        assert verified.status_code == 200
        body = verified.json()
        assert body["status"] == "verified"
        assert body["verification"] == "verified"

    # The record is visible through the finding detail read path.
    record = client.get(f"/api/findings/{app_sql_id}/remediation")
    assert record.status_code == 200
    assert record.json()["status"] == "verified"


def test_reprepare_resets_command_injection_too(client, fixture_repo):
    _, finding_id = _finding_of_type(client, fixture_repo, "command_injection")
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    client.post(
        f"/api/findings/{finding_id}/remediation/apply", json={"confirm": True}
    )
    from app.scan.run_store import get_scan_run_store

    runs = get_scan_run_store().runs_for_finding(finding_id)
    project_id = sorted({r.project_id for r in runs})[0]

    reprepared = client.post(f"/api/projects/{project_id}/reprepare")
    assert reprepared.status_code == 200
    rescan = client.post(f"/api/projects/{project_id}/scan").json()
    assert finding_id not in rescan["finding_ids"]
    verified = client.post(f"/api/findings/{finding_id}/remediation/verify")
    assert verified.json()["status"] == "verified"


def test_reprepare_unknown_project_404(client):
    response = client.post("/api/projects/does-not-exist/reprepare")
    assert response.status_code == 404


def test_reprepare_missing_workspace_copy_409(client, tmp_path):
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
    project_dir = (
        client.app.state.settings.workspace_dir / "projects" / project["id"]
    )
    shutil.rmtree(project_dir / "repo")
    response = client.post(f"/api/projects/{project['id']}/reprepare")
    assert response.status_code == 409


# ------------------------------------------------------- project deletion


def test_delete_project_cascades_remediation_records(client, fixture_repo):
    project, finding_id = _finding_of_type(
        client, fixture_repo, "sql_injection", sink_file="app.py"
    )
    client.post(f"/api/findings/{finding_id}/remediation/proposal")
    assert (
        client.get(f"/api/findings/{finding_id}/remediation").status_code == 200
    )
    deleted = client.delete(f"/api/projects/{project['id']}")
    assert deleted.status_code in (200, 204)
    assert client.get(f"/api/findings/{finding_id}/remediation").status_code == 404
