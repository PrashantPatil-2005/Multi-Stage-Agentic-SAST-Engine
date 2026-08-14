"""Semgrep benchmark API tests."""

import pytest

from app.benchmark.service import BenchmarkService, clear_reports
from tests.fake_semgrep_runner import FakeSemgrepRunner, finding


@pytest.fixture(autouse=True)
def _clean_reports():
    clear_reports()
    yield
    clear_reports()


@pytest.fixture(autouse=True)
def _inject_fake_runner(monkeypatch):
    """API must work without Semgrep installed: inject FakeSemgrepRunner."""

    def factory():
        return BenchmarkService(runner=FakeSemgrepRunner(available=False))

    monkeypatch.setattr("app.api.routes.benchmark.BenchmarkService", factory)


def test_benchmark_routes_registered(client):
    paths = client.app.openapi()["paths"]
    assert "post" in paths["/api/benchmarks/semgrep"]
    assert "get" in paths["/api/benchmarks/{benchmark_id}"]


def test_benchmark_runs_without_semgrep(client):
    response = client.post(
        "/api/benchmarks/semgrep", json={"fixture": "vulnerable_python_app"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["fixture"] == "vulnerable_python_app"
    assert body["ground_truth_count"] == 8
    assert body["our_result"]["available"] is True
    assert len(body["our_result"]["findings"]) == 5
    assert body["semgrep_result"]["available"] is False
    assert body["semgrep_result"]["findings"] == []
    assert body["semgrep_result"]["error"] is not None
    ours = next(m for m in body["metrics"] if m["tool"] == "our-sast")
    assert ours["true_positives"] == 5
    assert ours["precision"] == 1.0


def test_get_benchmark_report(client):
    created = client.post(
        "/api/benchmarks/semgrep", json={"fixture": "vulnerable_python_app"}
    ).json()
    fetched = client.get(f"/api/benchmarks/{created['benchmark_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["benchmark_id"] == created["benchmark_id"]
    assert fetched.json()["created_at"] == created["created_at"]


def test_unknown_benchmark_404(client):
    response = client.get("/api/benchmarks/does-not-exist")
    assert response.status_code == 404


def test_unknown_fixture_404(client):
    response = client.post(
        "/api/benchmarks/semgrep", json={"fixture": "nonexistent_fixture"}
    )
    assert response.status_code == 404
    assert "unknown fixture" in response.json()["detail"]


def test_invalid_fixture_name_422(client):
    response = client.post(
        "/api/benchmarks/semgrep", json={"fixture": "../../etc/passwd"}
    )
    assert response.status_code == 422


def test_blank_fixture_422(client):
    response = client.post("/api/benchmarks/semgrep", json={"fixture": "  "})
    assert response.status_code == 422


def test_missing_body_422(client):
    response = client.post("/api/benchmarks/semgrep", json={})
    assert response.status_code == 422


def test_benchmark_not_part_of_scan_pipeline(client):
    """POSTing a benchmark must not create findings/validations/proofs."""
    from app.prove.store import get_proof_store
    from app.validate.store import get_finding_store, get_validation_store

    response = client.post(
        "/api/benchmarks/semgrep", json={"fixture": "vulnerable_python_app"}
    )
    assert response.status_code == 200
    assert get_finding_store().get(response.json()["our_result"]["findings"][0]["fingerprint"]) is None
    assert get_validation_store().get(response.json()["our_result"]["findings"][0]["fingerprint"]) is None
    assert get_proof_store().get(response.json()["our_result"]["findings"][0]["fingerprint"]) is None


def test_comparison_present_with_fake_semgrep_findings(monkeypatch):
    fake = FakeSemgrepRunner(
        findings=[
            finding(vulnerability_type="sql_injection", line=15, function=None),
            finding(vulnerability_type="ssrf", file="app.py", line=40, function=None),
        ]
    )

    def factory():
        return BenchmarkService(runner=fake)

    monkeypatch.setattr("app.api.routes.benchmark.BenchmarkService", factory)
    from app.main import create_app
    from app.config import Settings
    from fastapi.testclient import TestClient

    with TestClient(create_app(Settings())) as client:
        body = client.post(
            "/api/benchmarks/semgrep", json={"fixture": "vulnerable_python_app"}
        ).json()
    assert body["semgrep_result"]["available"] is True
    assert len(body["comparison"]["shared_findings"]) == 2
    semgrep = next(m for m in body["metrics"] if m["tool"] == "semgrep")
    assert semgrep["true_positives"] == 2