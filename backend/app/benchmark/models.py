"""Benchmark contracts.

A benchmark compares our SAST engine and Semgrep against a *controlled
fixture repository* with explicit ground truth. Benchmark findings are
normalized so both tools can be matched on structural information.
"""

from datetime import datetime

from pydantic import BaseModel


class BenchmarkFinding(BaseModel):
    tool: str
    vulnerability_type: str
    file: str
    line: int
    function: str | None = None
    message: str
    fingerprint: str


class BenchmarkResult(BaseModel):
    tool: str
    available: bool
    findings: list[BenchmarkFinding] = []
    duration_ms: int | None = None
    error: str | None = None


class BenchmarkMetrics(BaseModel):
    tool: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    total_findings: int = 0


class BenchmarkComparison(BaseModel):
    shared_findings: list[BenchmarkFinding] = []
    ours_only: list[BenchmarkFinding] = []
    semgrep_only: list[BenchmarkFinding] = []
    shared_vulnerability_types: list[str] = []
    safe_cases_detected_incorrectly: list[str] = []


class BenchmarkReport(BaseModel):
    benchmark_id: str
    fixture: str
    ground_truth_count: int
    our_result: BenchmarkResult
    semgrep_result: BenchmarkResult
    metrics: list[BenchmarkMetrics]
    comparison: BenchmarkComparison
    created_at: datetime