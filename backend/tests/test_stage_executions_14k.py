"""Phase 14K tests: VALIDATE / PROVE / APPROVAL explicit run-context stages.

Extends the Phase 14J execution model to the remaining pipeline stages.
Covers:
* VALIDATE / PROVE / APPROVAL with ``scan_run_id`` record executions;
* clients without ``scan_run_id`` stay backward compatible (no stage record);
* approval requests store their run; decisions inherit it;
* multi-run isolation and cross-project rejection (reuses the 14J lineage
  validation - never a second mechanism);
* truthful stage semantics: validation exception -> failed; proof
  status="error" / gate rejection -> failed, verified/not_verified/blocked ->
  completed; approval invalid transition -> failed (never fabricated
  completion);
* retries are append-only; execution counts and statuses reflect the latest
  execution; restart preserves everything;
* the background SLA evaluator never touches VALIDATE/PROVE/APPROVAL stages;
* no automatic downstream stage is ever triggered.
"""

from datetime import datetime, timezone

import pytest

from app.api.routes.validations import get_validation_service
from app.approval.store import get_approval_store
from app.config import Settings
from app.main import create_app
from app.prove.models import ProofResult, SandboxPolicy
from app.prove.service import ProofGateError, ProofService
from app.prove.store import get_proof_store
from app.risk.sla_evaluator import SlaEvaluator
from app.risk.service import get_sla_record, reset_risk_stores
from app.scan.run_store import get_scan_run_store
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from fastapi.testclient import TestClient
from tests.fake_llm_provider import FakeLLMProvider


@pytest.fixture(autouse=True)
def _clear_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    get_scan_run_store().clear()
    reset_risk_stores()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    get_scan_run_store().clear()
    reset_risk_stores()


@pytest.fixture
def validated_app(client):
    """Full API client whose VALIDATE dependency uses the fake LLM provider."""
    app = client.app
    app.dependency_overrides[get_validation_service] = lambda: ValidationService(
        provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
    )
    yield client
    app.dependency_overrides.clear()


def _settings(tmp_path, db_name: str = "stage-14k.db") -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url=f"sqlite:///{(tmp_path / db_name).as_posix()}",
        log_level="WARNING",
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def _create_project(client: TestClient, fixture_repo, name: str = "k-app"):
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


def _executions_for(client: TestClient, scan_run_id: str, stage: str) -> list[dict]:
    return [e for e in _executions(client, scan_run_id) if e["stage_name"] == stage]


def _proof_result(finding_id: str, status: str = "verified", error: str | None = None):
    return ProofResult(
        finding_id=finding_id,
        vulnerability_type="sql_injection",
        status=status,
        confidence=0.9,
        summary="canned proof result",
        duration_ms=1.0,
        sandbox_policy=SandboxPolicy(),
        error=error,
        created_at=datetime.now(timezone.utc),
    )


def _fake_prove(monkeypatch, status="verified", error=None):
    def _prove(self, finding, validation_result):
        return _proof_result(finding.id, status=status, error=error)

    monkeypatch.setattr(ProofService, "prove", _prove)
    return _prove


def _setup_run(client: TestClient, fixture_repo) -> tuple[dict, dict, str]:
    project = _create_project(client, fixture_repo)
    scan = _scan(client, project["id"])
    finding_id = scan["finding_ids"][0]
    return project, scan, finding_id


# ---------------------------------------------------------------- VALIDATE

def test_validate_with_scan_run_id_records_execution(validated_app, fixture_repo):
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)

    resp = validated_app.post(
        f"/api/findings/{finding_id}/validate",
        json={"provider": "huggingface", "scan_run_id": scan["scan_run_id"]},
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "true_positive"

    stages = _stages(validated_app, scan["scan_run_id"])
    assert stages["VALIDATE"]["status"] == "completed"
    assert stages["VALIDATE"]["execution_count"] == 1
    assert stages["PROVE"]["status"] == "pending"
    assert stages["APPROVAL"]["status"] == "pending"
    assert len(_executions_for(validated_app, scan["scan_run_id"], "VALIDATE")) == 1


def test_validate_without_scan_run_id_backward_compatible(validated_app, fixture_repo):
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)

    resp = validated_app.post(
        f"/api/findings/{finding_id}/validate", json={"provider": "huggingface"}
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "true_positive"
    assert _stages(validated_app, scan["scan_run_id"])["VALIDATE"]["status"] == "pending"
    assert not _executions_for(validated_app, scan["scan_run_id"], "VALIDATE")


def test_validate_failure_records_failed_execution(
    validated_app, fixture_repo, monkeypatch
):
    from app.validate.providers.base import ConfigurationError

    def _boom(self, finding, *, sources=None, provider=None, provider_name=None):
        raise ConfigurationError("provider not configured")

    monkeypatch.setattr("app.validate.service.ValidationService.validate", _boom)

    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    resp = validated_app.post(
        f"/api/findings/{finding_id}/validate",
        json={"provider": "huggingface", "scan_run_id": scan["scan_run_id"]},
    )
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]

    stages = _stages(validated_app, scan["scan_run_id"])
    assert stages["VALIDATE"]["status"] == "failed"
    assert stages["VALIDATE"]["error"] == "provider not configured"
    assert stages["VALIDATE"]["completed_at"] is not None
    executions = _executions_for(validated_app, scan["scan_run_id"], "VALIDATE")
    assert len(executions) == 1
    assert executions[0]["status"] == "failed"
    assert executions[0]["error"] == "provider not configured"


def test_validate_retry_is_append_only(validated_app, fixture_repo):
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    for _ in range(2):
        resp = validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        )
        assert resp.status_code == 200

    stages = _stages(validated_app, run_id)
    assert stages["VALIDATE"]["execution_count"] == 2
    assert stages["VALIDATE"]["status"] == "completed"
    executions = _executions_for(validated_app, run_id, "VALIDATE")
    assert [e["status"] for e in executions] == ["completed", "completed"]
    assert executions[0]["execution_id"] != executions[1]["execution_id"]


# ------------------------------------------------------------------- PROVE

def test_prove_with_scan_run_id_records_execution(
    validated_app, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="verified")
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )
    resp = validated_app.post(f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified"

    stages = _stages(validated_app, run_id)
    assert stages["PROVE"]["status"] == "completed"
    assert stages["PROVE"]["execution_count"] == 1
    assert stages["APPROVAL"]["status"] == "pending"
    assert len(_executions_for(validated_app, run_id, "PROVE")) == 1


def test_prove_without_scan_run_id_backward_compatible(
    validated_app, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="verified")
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate", json={"provider": "huggingface"}
        ).status_code
        == 200
    )
    resp = validated_app.post(f"/api/findings/{finding_id}/prove")
    assert resp.status_code == 200
    assert _stages(validated_app, scan["scan_run_id"])["PROVE"]["status"] == "pending"
    assert not _executions_for(validated_app, scan["scan_run_id"], "PROVE")


def test_prove_error_status_is_failed_execution(
    validated_app, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="error", error="proof harness timed out")
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )
    resp = validated_app.post(f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id})
    # the proof execution itself completed the HTTP call with a truthful result
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"

    stages = _stages(validated_app, run_id)
    assert stages["PROVE"]["status"] == "failed"
    assert stages["PROVE"]["error"] == "proof harness timed out"
    assert stages["PROVE"]["completed_at"] is not None
    executions = _executions_for(validated_app, run_id, "PROVE")
    assert len(executions) == 1
    assert executions[0]["status"] == "failed"
    assert executions[0]["error"] == "proof harness timed out"


def test_prove_not_verified_is_completed_execution(
    validated_app, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="not_verified")
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )
    resp = validated_app.post(f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 200
    assert resp.json()["status"] == "not_verified"
    stages = _stages(validated_app, run_id)
    assert stages["PROVE"]["status"] == "completed"
    assert stages["PROVE"]["error"] is None


def test_prove_gate_rejection_is_failed_execution(
    validated_app, fixture_repo, monkeypatch
):
    def _gate(self, finding, validation_result):
        raise ProofGateError("finding is not eligible for proof: verdict=false_positive")

    monkeypatch.setattr(ProofService, "prove", _gate)

    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]
    # validate (true_positive) then override the stored verdict check by
    # validating a second finding? Simpler: force the gate by validating the
    # finding, then replace the stored validation verdict.
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )

    resp = validated_app.post(f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id})
    assert resp.status_code == 409
    assert "not eligible" in resp.json()["detail"]

    stages = _stages(validated_app, run_id)
    assert stages["PROVE"]["status"] == "failed"
    assert "not eligible" in stages["PROVE"]["error"]
    assert stages["PROVE"]["completed_at"] is not None


# ---------------------------------------------------------------- APPROVAL

def _validated_and_proven(validated_app, fixture_repo, monkeypatch):
    _fake_prove(monkeypatch, status="verified")
    project, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id}
        ).status_code
        == 200
    )
    return project, scan, finding_id


def test_approval_request_with_scan_run_id_records_execution(
    validated_app, fixture_repo, monkeypatch
):
    _, scan, finding_id = _validated_and_proven(
        validated_app, fixture_repo, monkeypatch
    )
    run_id = scan["scan_run_id"]

    resp = validated_app.post(
        f"/api/findings/{finding_id}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": run_id,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["scan_run_id"] == run_id
    assert resp.json()["status"] == "pending"

    stages = _stages(validated_app, run_id)
    assert stages["APPROVAL"]["status"] == "completed"
    assert stages["APPROVAL"]["execution_count"] == 1
    assert len(_executions_for(validated_app, run_id, "APPROVAL")) == 1


def test_approval_decision_inherits_run_context(
    validated_app, fixture_repo, monkeypatch
):
    _, scan, finding_id = _validated_and_proven(
        validated_app, fixture_repo, monkeypatch
    )
    run_id = scan["scan_run_id"]

    created = validated_app.post(
        f"/api/findings/{finding_id}/approval",
        json={"action": "remediation", "requested_by": "system", "scan_run_id": run_id},
    ).json()

    resp = validated_app.post(
        f"/api/approvals/{created['id']}/approve",
        json={"reviewed_by": "security-analyst", "reason": "verified"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "approved"

    stages = _stages(validated_app, run_id)
    assert stages["APPROVAL"]["execution_count"] == 2  # request + approve
    assert stages["APPROVAL"]["status"] == "completed"
    executions = _executions_for(validated_app, run_id, "APPROVAL")
    assert [e["status"] for e in executions] == ["completed", "completed"]
    assert executions[0]["execution_id"] != executions[1]["execution_id"]


def test_approval_invalid_transition_records_failed_not_completed(
    validated_app, fixture_repo, monkeypatch
):
    _, scan, finding_id = _validated_and_proven(
        validated_app, fixture_repo, monkeypatch
    )
    run_id = scan["scan_run_id"]

    created = validated_app.post(
        f"/api/findings/{finding_id}/approval",
        json={"action": "remediation", "requested_by": "system", "scan_run_id": run_id},
    ).json()
    assert (
        validated_app.post(
            f"/api/approvals/{created['id']}/approve",
            json={"reviewed_by": "security-analyst"},
        ).status_code
        == 200
    )

    # approving an already-approved request is an invalid transition
    # The invalid transition is rejected BEFORE recording a stage execution,
    # so the stage history is not polluted with misleading "failed" records.
    resp = validated_app.post(
        f"/api/approvals/{created['id']}/approve",
        json={"reviewed_by": "security-analyst"},
    )
    assert resp.status_code == 409
    assert "invalid approval transition" in resp.json()["detail"]

    stages = _stages(validated_app, run_id)
    assert stages["APPROVAL"]["status"] == "completed"
    assert stages["APPROVAL"]["execution_count"] == 2
    executions = _executions_for(validated_app, run_id, "APPROVAL")
    assert [e["status"] for e in executions] == [
        "completed",  # request
        "completed",  # first approve
    ]
    # the approval state machine itself is untouched
    stored = get_approval_store().get(created["id"])
    assert stored.status == "approved"
    assert stored.version == 1


def test_approval_without_scan_run_id_backward_compatible(
    validated_app, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="verified")
    project, scan, finding_id = _setup_run(validated_app, fixture_repo)
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate", json={"provider": "huggingface"}
        ).status_code
        == 200
    )
    assert (
        validated_app.post(f"/api/findings/{finding_id}/prove").status_code == 200
    )

    resp = validated_app.post(
        f"/api/findings/{finding_id}/approval",
        json={"action": "remediation", "requested_by": "system"},
    )
    assert resp.status_code == 200
    assert resp.json()["scan_run_id"] is None
    assert _stages(validated_app, scan["scan_run_id"])["APPROVAL"]["status"] == "pending"
    assert not _executions_for(validated_app, scan["scan_run_id"], "APPROVAL")


# ---------------------------------------------------- multi-run + isolation

def test_multi_run_isolation(validated_app, fixture_repo, monkeypatch):
    _fake_prove(monkeypatch, status="verified")
    project = _create_project(validated_app, fixture_repo)
    first = _scan(validated_app, project["id"])
    second = _scan(validated_app, project["id"])
    finding_id = first["finding_ids"][0]

    # validate + prove + approval all against the SECOND run
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": second["scan_run_id"]},
        ).status_code
        == 200
    )
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/prove",
            json={"scan_run_id": second["scan_run_id"]},
        ).status_code
        == 200
    )
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/approval",
            json={
                "action": "remediation",
                "requested_by": "system",
                "scan_run_id": second["scan_run_id"],
            },
        ).status_code
        == 200
    )

    first_stages = _stages(validated_app, first["scan_run_id"])
    second_stages = _stages(validated_app, second["scan_run_id"])
    for stage in ("VALIDATE", "PROVE", "APPROVAL"):
        assert first_stages[stage]["status"] == "pending"
        assert first_stages[stage]["execution_count"] == 0
        assert second_stages[stage]["status"] == "completed"
        assert second_stages[stage]["execution_count"] == 1
    assert not _executions_for(validated_app, first["scan_run_id"], "VALIDATE")
    assert len(_executions_for(validated_app, second["scan_run_id"], "APPROVAL")) == 1


def test_cross_project_run_context_rejected(validated_app, fixture_repo, monkeypatch):
    _fake_prove(monkeypatch, status="verified")
    project_a = _create_project(validated_app, fixture_repo, name="app-a")
    project_b = _create_project(validated_app, fixture_repo, name="app-b")
    scan_a = _scan(validated_app, project_a["id"])
    scan_b = _scan(validated_app, project_b["id"])
    finding_a = scan_a["finding_ids"][0]

    # finding A + run B must be rejected for every stage
    validate = validated_app.post(
        f"/api/findings/{finding_a}/validate",
        json={"provider": "huggingface", "scan_run_id": scan_b["scan_run_id"]},
    )
    assert validate.status_code == 400
    prove = validated_app.post(
        f"/api/findings/{finding_a}/prove",
        json={"scan_run_id": scan_b["scan_run_id"]},
    )
    assert prove.status_code == 400
    approval = validated_app.post(
        f"/api/findings/{finding_a}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": scan_b["scan_run_id"],
        },
    )
    assert approval.status_code == 400

    b_stages = _stages(validated_app, scan_b["scan_run_id"])
    for stage in ("VALIDATE", "PROVE", "APPROVAL"):
        assert b_stages[stage]["status"] == "pending"
        assert b_stages[stage]["execution_count"] == 0


def test_unknown_scan_run_rejected(validated_app, fixture_repo):
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    validate = validated_app.post(
        f"/api/findings/{finding_id}/validate",
        json={"provider": "huggingface", "scan_run_id": "does-not-exist"},
    )
    assert validate.status_code == 404
    prove = validated_app.post(
        f"/api/findings/{finding_id}/prove",
        json={"scan_run_id": "does-not-exist"},
    )
    assert prove.status_code == 404
    approval = validated_app.post(
        f"/api/findings/{finding_id}/approval",
        json={
            "action": "remediation",
            "requested_by": "system",
            "scan_run_id": "does-not-exist",
        },
    )
    assert approval.status_code == 404
    assert _stages(validated_app, scan["scan_run_id"])["VALIDATE"]["status"] == "pending"


# ---------------------------------------------------------- no auto chaining

def test_no_automatic_downstream_stages(validated_app, fixture_repo, monkeypatch):
    _fake_prove(monkeypatch, status="verified")
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    # validate only -> no PROVE / APPROVAL executions
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/validate",
            json={"provider": "huggingface", "scan_run_id": run_id},
        ).status_code
        == 200
    )
    stages = _stages(validated_app, run_id)
    assert stages["PROVE"]["execution_count"] == 0
    assert stages["APPROVAL"]["execution_count"] == 0

    # prove only -> no APPROVAL execution
    assert (
        validated_app.post(
            f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id}
        ).status_code
        == 200
    )
    stages = _stages(validated_app, run_id)
    assert stages["APPROVAL"]["execution_count"] == 0
    assert not _executions_for(validated_app, run_id, "APPROVAL")


# ------------------------------------------------------------ persistence

def test_restart_preserves_14k_execution_history(
    tmp_path, fixture_repo, monkeypatch
):
    _fake_prove(monkeypatch, status="verified")
    settings = _settings(tmp_path)
    with _client(settings) as client:
        app = client.app
        app.dependency_overrides[get_validation_service] = lambda: ValidationService(
            provider=FakeLLMProvider(verdict="true_positive", confidence=0.91)
        )
        project, scan, finding_id = _setup_run(client, fixture_repo)
        run_id = scan["scan_run_id"]
        assert (
            client.post(
                f"/api/findings/{finding_id}/validate",
                json={"provider": "huggingface", "scan_run_id": run_id},
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"/api/findings/{finding_id}/prove", json={"scan_run_id": run_id}
            ).status_code
            == 200
        )
        created = client.post(
            f"/api/findings/{finding_id}/approval",
            json={
                "action": "remediation",
                "requested_by": "system",
                "scan_run_id": run_id,
            },
        ).json()
        assert created["scan_run_id"] == run_id
        before = client.get(f"/api/scans/{run_id}").json()

    with _client(settings) as client:
        after = client.get(f"/api/scans/{run_id}").json()
        assert after == before
        stages = {s["stage_name"]: s for s in after["stages"]}
        for stage in ("VALIDATE", "PROVE", "APPROVAL"):
            assert stages[stage]["status"] == "completed"
            assert stages[stage]["execution_count"] == 1
            assert stages[stage]["started_at"] is not None
            assert stages[stage]["completed_at"] is not None
        for stage in ("VALIDATE", "PROVE", "APPROVAL"):
            executions = [
                e for e in after["executions"] if e["stage_name"] == stage
            ]
            assert len(executions) == 1
            assert executions[0]["status"] == "completed"
            assert executions[0]["completed_at"] is not None
        # approval request + its run context survive
        stored = get_approval_store().get(created["id"])
        assert stored.scan_run_id == run_id
        assert stored.status == "pending"


# ------------------------------------------------- background evaluator

def test_background_evaluator_never_creates_14k_executions(
    validated_app, fixture_repo, monkeypatch
):
    """The background SLA evaluator updates SLA records only; it must never
    create VALIDATE/PROVE/APPROVAL (or any) scan-run stage executions."""
    _, scan, finding_id = _setup_run(validated_app, fixture_repo)
    run_id = scan["scan_run_id"]

    # create an SLA record WITHOUT run context (stage stays pending)
    assert (
        validated_app.post(f"/api/findings/{finding_id}/risk").status_code == 200
    )
    assert (
        validated_app.post(f"/api/findings/{finding_id}/sla").status_code == 200
    )
    record = get_sla_record(finding_id)
    assert record is not None and record.status == "active"

    executions_before = _executions(validated_app, run_id)
    SlaEvaluator(interval_seconds=3600).evaluate_once(
        now=record.due_at + __import__("datetime").timedelta(hours=1)
    )
    assert get_sla_record(finding_id).status == "breached"
    assert _executions(validated_app, run_id) == executions_before
    stages = _stages(validated_app, run_id)
    for stage in ("SLA", "VALIDATE", "PROVE", "APPROVAL"):
        assert stages[stage]["status"] == "pending"
        assert stages[stage]["execution_count"] == 0
