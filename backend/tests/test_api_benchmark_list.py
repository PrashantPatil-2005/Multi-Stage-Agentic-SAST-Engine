"""Read-only benchmark list endpoint tests.

The list endpoint is presentation-only: it reads stored BenchmarkReport
values and never computes or fabricates metrics.
"""

from datetime import datetime, timezone

import pytest

from app.api.routes.benchmark import _to_summary
from app.benchmark.models import (
    BenchmarkComparison,
    BenchmarkMetrics,
    BenchmarkReport,
    BenchmarkResult,
)
from app.benchmark.service import BenchmarkService, clear_reports
from tests.fake_semgrep_runner import FakeSemgrepRunner, finding

VULNERABLE_FINDINGS = [
    finding(vulnerability_type="sql_injection", line=12),
    finding(vulnerability_type="command_injection", line=33),
    finding(vulnerability_type="ssrf", line=37),
    finding(vulnerability_type="sql_injection", file="db.py", line=14),
    finding(vulnerability_type="sql_injection", file="db.py", line=19),
]


@pytest.fixture(autouse=True)
def _clean_reports():
    clear_reports()
    yield
    clear_reports()


def _run(fixture: str = "vulnerable_python_app", runner: FakeSemgrepRunner | None = None) -> BenchmarkReport:
    service = BenchmarkService(runner=runner or FakeSemgrepRunner(available=False))
    return service.run(fixture)


def test_list_route_registered(client):
    paths = client.app.openapi()["paths"]
    assert "get" in paths["/api/benchmarks"]


def test_list_empty_state(client):
    response = client.get("/api/benchmarks")
    assert response.status_code == 200
    body = response.json()
    assert body == {"has_reports": False, "reports": []}


def test_list_returns_single_report_summary(client):
    report = _run(runner=FakeSemgrepRunner(findings=VULNERABLE_FINDINGS))
    response = client.get("/api/benchmarks")
    assert response.status_code == 200
    body = response.json()
    assert body["has_reports"] is True
    assert len(body["reports"]) == 1
    summary = body["reports"][0]
    assert summary["benchmark_id"] == report.benchmark_id
    assert summary["fixture"] == "vulnerable_python_app"
    assert datetime.fromisoformat(summary["created_at"]) == report.created_at
    assert summary["semgrep_available"] is True
    assert summary["semgrep_error"] is None
    assert summary["our_f1"] == 1.0
    assert summary["semgrep_f1"] == 1.0
    assert summary["ground_truth_cases"] == 8
    assert summary["vulnerable_cases"] == 5
    assert summary["safe_cases"] == 3


def test_list_semgrep_unavailable_state(client):
    _run(runner=FakeSemgrepRunner(available=False))
    response = client.get("/api/benchmarks")
    body = response.json()
    summary = body["reports"][0]
    assert summary["semgrep_available"] is False
    assert summary["semgrep_error"] is not None
    assert summary["semgrep_f1"] is None
    assert summary["our_f1"] == 1.0


def test_list_never_fabricates_semgrep_metrics(client):
    """When Semgrep did not run there must be no semgrep f1 and no semgrep
    metrics entry in the stored report itself."""
    report = _run(runner=FakeSemgrepRunner(available=False))
    assert [m.tool for m in report.metrics] == ["our-sast"]
    response = client.get("/api/benchmarks")
    summary = response.json()["reports"][0]
    assert summary["semgrep_f1"] is None
    assert "semgrep" not in {m["tool"] for m in report.model_dump()["metrics"]}


def test_list_returns_newest_first(client):
    first = _run(runner=FakeSemgrepRunner(available=False))
    second = _run(
        runner=FakeSemgrepRunner(
            available=True, findings=[finding(vulnerability_type="sql_injection", line=12)]
        )
    )
    response = client.get("/api/benchmarks")
    body = response.json()
    assert body["has_reports"] is True
    assert len(body["reports"]) == 2
    ids = [r["benchmark_id"] for r in body["reports"]]
    assert set(ids) == {first.benchmark_id, second.benchmark_id}
    timestamps = [
        datetime.fromisoformat(r["created_at"]) for r in body["reports"]
    ]
    assert timestamps == sorted(timestamps, reverse=True)
    assert second.benchmark_id in ids[:1] or timestamps[0] >= timestamps[1]


def test_list_returns_full_ground_truth_breakdown_for_known_fixture(client):
    _run(runner=FakeSemgrepRunner(findings=VULNERABLE_FINDINGS))
    summary = client.get("/api/benchmarks").json()["reports"][0]
    assert summary["vulnerable_cases"] + summary["safe_cases"] == summary["ground_truth_cases"]


def test_summary_unknown_fixture_has_no_ground_truth_breakdown():
    """A stored report for a fixture the ground truth module does not know
    must expose None counts instead of fabricated 0s."""
    report = BenchmarkReport(
        benchmark_id="crafted-report",
        fixture="unknown_fixture",
        ground_truth_count=0,
        our_result=BenchmarkResult(tool="our-sast", available=True, findings=[]),
        semgrep_result=BenchmarkResult(
            tool="semgrep",
            available=False,
            findings=[],
            error="semgrep CLI not installed; benchmark unavailable",
        ),
        metrics=[BenchmarkMetrics(tool="our-sast")],
        comparison=BenchmarkComparison(),
        created_at=datetime.now(timezone.utc),
    )
    summary = _to_summary(report)
    assert summary.vulnerable_cases is None
    assert summary.safe_cases is None
    assert summary.semgrep_f1 is None
    assert summary.our_f1 is None
