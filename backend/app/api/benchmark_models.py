"""Read-only response models for the benchmark list endpoint.

Presentation-only aggregation of stored BenchmarkReport values. This never
modifies benchmark models, metrics or calculation logic; f1 values are read
verbatim from the stored per-tool BenchmarkMetrics entries and the ground
truth breakdown comes from the ground truth module itself.
"""

from datetime import datetime

from pydantic import BaseModel


class BenchmarkSummary(BaseModel):
    benchmark_id: str
    fixture: str
    created_at: datetime
    semgrep_available: bool
    semgrep_error: str | None
    our_f1: float | None
    semgrep_f1: float | None
    ground_truth_cases: int
    vulnerable_cases: int | None
    safe_cases: int | None


class BenchmarkList(BaseModel):
    has_reports: bool
    reports: list[BenchmarkSummary]
