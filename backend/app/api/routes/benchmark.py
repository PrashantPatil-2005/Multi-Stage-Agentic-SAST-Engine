"""Semgrep benchmark API (optional evaluation path — never part of the scan pipeline).

POST /api/benchmarks/semgrep   - run our engine + Semgrep on a controlled fixture
GET  /api/benchmarks/{benchmark_id} - stored benchmark report

Errors: 404 (unknown fixture / unknown benchmark), 422 (invalid fixture name).
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.benchmark.models import BenchmarkReport
from app.benchmark.service import (
    BenchmarkService,
    InvalidFixtureNameError,
    UnknownFixtureError,
    get_report,
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