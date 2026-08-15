"""Read-only repositories summary API tests."""

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.approval.store import get_approval_store
from app.prove.service import ProofService
from app.prove.store import get_proof_store
from app.risk.service import (
    RiskService,
    SLAService,
    all_risk_assessments,
    record_risk_assessment,
    record_sla_record,
    reset_risk_stores,
)
from app.validate.service import ValidationService
from app.validate.store import get_finding_store, get_validation_store
from tests.fake_llm_provider import FakeLLMProvider
from tests.scan_test_helpers import scan_fixture_files, scan_sources


@pytest.fixture(autouse=True)
def clean_stores():
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()
    yield
    get_finding_store().clear()
    get_validation_store().clear()
    get_proof_store().clear()
    get_approval_store().clear()
    reset_risk_stores()


def _register_findings(*files: str):
    findings = scan_fixture_files(*files).findings
    for finding in findings:
        get_finding_store().add(finding)
    return findings


def _assess(finding, priority=None, score=None):
    assessment = RiskService().assess(finding)
    if priority is not None or score is not None:
        assessment = assessment.model_copy(
            update={
                "priority": priority or assessment.priority,
                "risk_score": score if score is not None else assessment.risk_score,
            }
        )
    record_risk_assessment(assessment)
    return assessment


def _validate(finding, verdict):
    validation = ValidationService(
        provider=FakeLLMProvider(verdict=verdict, confidence=0.9)
    ).validate(finding)
    get_validation_store().record(validation)
    return validation


def _prove(finding):
    validation = _validate(finding, "true_positive")
    proof = ProofService().prove(finding, validation)
    get_proof_store().record(proof)
    return proof


def _sla(finding, assessment, status="active"):
    sla = SLAService().create_sla(
        assessment, started_at=datetime.now(timezone.utc) - timedelta(days=1)
    )
    if status != "active":
        record, _ = SLAService().check_sla(
            sla, now=datetime.now(timezone.utc) + timedelta(days=10)
        )
        sla = record
    record_sla_record(sla)
    return sla


def _create_project(client, fixture_repo, name="demo-app"):
    response = client.post(
        "/api/projects",
        json={
            "name": name,
            "source_type": "directory",
            "location": str(fixture_repo),
            "language": "python",
        },
    )
    assert response.status_code == 201
    return response.json()


def _normalize(iso: str) -> datetime:
    """SQLite stores naive datetimes; the POST response is tz-aware UTC."""
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(tzinfo=None)


def _get(client):
    response = client.get("/api/repositories")
    assert response.status_code == 200
    return response.json()


def test_repositories_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/repositories"]


def test_empty_state(client):
    body = _get(client)
    assert body == {"has_repositories": False, "repositories": []}


def test_project_without_findings_has_no_summaries(client, fixture_repo):
    project = _create_project(client, fixture_repo)
    body = _get(client)
    assert body["has_repositories"] is True
    assert len(body["repositories"]) == 1
    row = body["repositories"][0]
    assert row["project_id"] == project["id"]
    assert row["name"] == "demo-app"
    assert row["source_type"] == "directory"
    assert row["status"] == "prepared"
    assert _normalize(row["created_at"]) == _normalize(project["created_at"])
    assert row["findings"] is None
    assert row["risk"] is None
    assert row["validation"] is None
    assert row["proof"] is None
    assert row["sla"] is None


def test_finding_aggregation_by_snapshot_files(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py", "db.py")
    for finding in findings:
        _assess(finding)

    body = _get(client)
    row = body["repositories"][0]
    assert row["findings"]["total"] == len(findings)
    assert sum(row["findings"]["by_priority"].values()) == len(findings)


def test_priority_aggregation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    _assess(findings[0], priority="P0", score=95)
    _assess(findings[1], priority="P1", score=75)

    row = _get(client)["repositories"][0]
    assert row["findings"]["by_priority"] == {
        "P0": 1,
        "P1": 1,
        "P2": 0,
        "P3": 0,
        "P4": 0,
    }
    assert row["findings"]["highest_priority"] == "P0"
    assert row["risk"]["highest_priority"] == "P0"
    assert row["risk"]["highest_risk_score"] == 95
    assert row["risk"]["top_finding_id"] == findings[0].id


def test_risk_aggregation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    _assess(findings[0], priority="P2", score=60)

    row = _get(client)["repositories"][0]
    assert row["risk"]["available"] is True
    assert row["risk"]["highest_risk_score"] == 60
    assert row["risk"]["highest_priority"] == "P2"
    assert row["risk"]["top_finding_id"] == findings[0].id


def test_validation_aggregation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    _validate(findings[0], "true_positive")
    _validate(findings[1], "false_positive")
    _validate(findings[2], "uncertain")

    row = _get(client)["repositories"][0]
    assert row["validation"] == {
        "available": True,
        "true_positive": 1,
        "false_positive": 1,
        "uncertain": 1,
    }


def test_proof_aggregation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    _prove(findings[0])
    _prove(findings[1])

    row = _get(client)["repositories"][0]
    assert row["proof"]["available"] is True
    assert row["proof"]["verified"] == 2
    assert row["proof"]["not_verified"] == 0
    assert row["proof"]["blocked"] == 0
    assert row["proof"]["error"] == 0


def test_sla_aggregation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    active = _assess(findings[0], priority="P1")
    _sla(findings[0], active, status="active")
    breached = _assess(findings[1], priority="P0")
    _sla(findings[1], breached, status="breached")

    row = _get(client)["repositories"][0]
    assert row["sla"]["available"] is True
    assert row["sla"]["active"] == 1
    assert row["sla"]["breached"] == 1
    assert row["sla"]["resolved"] == 0


def test_missing_optional_data_shows_no_risk_but_findings(client, fixture_repo):
    _create_project(client, fixture_repo)
    _register_findings("app.py")

    row = _get(client)["repositories"][0]
    assert row["findings"]["total"] == 3
    assert row["findings"]["by_priority"] == {
        "P0": 0,
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0,
    }
    assert row["findings"]["highest_priority"] is None
    assert row["risk"] is None
    assert row["validation"] is None
    assert row["proof"] is None
    assert row["sla"] is None


def test_repository_association_convention(client, fixture_repo):
    _create_project(client, fixture_repo)
    _register_findings("app.py")
    _register_findings("utils.py", "config.py")

    row = _get(client)["repositories"][0]
    total = row["findings"]["total"]
    scan = scan_fixture_files("app.py", "utils.py", "config.py").findings
    assert total == len(scan)


def test_findings_outside_snapshot_are_not_attributed(client, fixture_repo):
    _create_project(client, fixture_repo)
    get_finding_store().add(scan_fixture_files("app.py").findings[0])
    external = scan_sources(
        {
            "vendor/external_app.py": (
                Path(__file__).parent / "fixtures" / "vulnerable_python_app" / "app.py"
            ).read_text(encoding="utf-8"),
        }
    ).findings
    assert external
    for finding in external:
        get_finding_store().add(finding)

    row = _get(client)["repositories"][0]
    assert row["findings"]["total"] == 1


def test_missing_snapshot_yields_no_summaries(client, fixture_repo, settings):
    project = _create_project(client, fixture_repo)
    project_dir = settings.workspace_dir / "projects" / project["id"]
    assert project_dir.exists()
    shutil.rmtree(project_dir)

    row = _get(client)["repositories"][0]
    assert row["project_id"] == project["id"]
    assert row["findings"] is None
    assert row["risk"] is None
    assert row["validation"] is None
    assert row["proof"] is None
    assert row["sla"] is None


def test_newest_first_ordering(client, fixture_repo):
    first = _create_project(client, fixture_repo, name="first-app")
    second = _create_project(client, fixture_repo, name="second-app")

    rows = _get(client)["repositories"]
    assert [row["name"] for row in rows] == ["second-app", "first-app"]
    assert rows[0]["project_id"] == second["id"]
    assert rows[1]["project_id"] == first["id"]


def test_no_mutation(client, fixture_repo):
    _create_project(client, fixture_repo)
    findings = _register_findings("app.py")
    for finding in findings:
        _assess(finding)

    before = (
        [f.id for f in get_finding_store().all()],
        [r.finding_id for r in all_risk_assessments()],
        [p.finding_id for p in get_proof_store().all()],
    )
    first = _get(client)
    second = _get(client)
    after = (
        [f.id for f in get_finding_store().all()],
        [r.finding_id for r in all_risk_assessments()],
        [p.finding_id for p in get_proof_store().all()],
    )
    assert first == second
    assert before == after
