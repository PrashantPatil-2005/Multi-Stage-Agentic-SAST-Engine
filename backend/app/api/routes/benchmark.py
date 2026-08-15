"""Semgrep benchmark API (optional evaluation path — never part of the scan pipeline).

POST /api/benchmarks/semgrep   - run our engine + Semgrep on a controlled fixture
GET  /api/benchmarks          - read-only list of stored benchmark reports
GET  /api/benchmarks/{benchmark_id} - stored benchmark report

Errors: 404 (unknown fixture / unknown benchmark), 422 (invalid fixture name).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.api.benchmark_models import BenchmarkList, BenchmarkSummary
from app.benchmark.ground_truth import get_ground_truth
from app.benchmark.models import BenchmarkReport
from app.benchmark.service import (
    BenchmarkService,
    InvalidFixtureNameError,
    UnknownFixtureError,
    get_report,
    list_reports,
)

router = APIRouter(prefix="/benchmarks", tags=["benchmark"])


class BenchmarkRequest(BaseModel):
    fixture: str

    @field_validator("fixture")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("fixture must not be blank")
        return value.strip()


def _service() -> BenchmarkService:
    return BenchmarkService()


def _metric_f1(report: BenchmarkReport, tool: str) -> float | None:
    return next((m.f1 for m in report.metrics if m.tool == tool), None)


def _to_summary(report: BenchmarkReport) -> BenchmarkSummary:
    cases = get_ground_truth(report.fixture)
    vulnerable = len([c for c in cases if c.expected_vulnerable])
    return BenchmarkSummary(
        benchmark_id=report.benchmark_id,
        fixture=report.fixture,
        created_at=report.created_at,
        semgrep_available=report.semgrep_result.available,
        semgrep_error=report.semgrep_result.error,
        our_f1=_metric_f1(report, "our-sast"),
        semgrep_f1=_metric_f1(report, "semgrep"),
        ground_truth_cases=report.ground_truth_count,
        vulnerable_cases=vulnerable if cases else None,
        safe_cases=(len(cases) - vulnerable) if cases else None,
    )


@router.get("", response_model=BenchmarkList)
def list_benchmarks() -> BenchmarkList:
    reports = list_reports()
    return BenchmarkList(
        has_reports=bool(reports),
        reports=[_to_summary(r) for r in reports],
    )


@router.post("/semgrep", response_model=BenchmarkReport)
def run_benchmark(body: BenchmarkRequest) -> BenchmarkReport:
    try:
        return _service().run(body.fixture)
    except InvalidFixtureNameError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except UnknownFixtureError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{benchmark_id}", response_model=BenchmarkReport)
def get_benchmark(benchmark_id: str) -> BenchmarkReport:
    report = get_report(benchmark_id)
    if report is None:
        raise HTTPException(
            status_code=404, detail=f"benchmark not found: {benchmark_id}"
        )
    return report