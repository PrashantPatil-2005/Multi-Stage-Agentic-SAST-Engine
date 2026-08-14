"""Optional Semgrep benchmarking module (never part of the production pipeline)."""

from app.benchmark.ground_truth import (
    FIXTURE_GROUND_TRUTH,
    KNOWN_FIXTURES,
    GroundTruthCase,
    get_ground_truth,
    safe_cases,
    vulnerable_cases,
)
from app.benchmark.matcher import DEFAULT_TOLERANCE, BenchmarkMatcher
from app.benchmark.metrics import compute_metrics
from app.benchmark.models import (
    BenchmarkComparison,
    BenchmarkFinding,
    BenchmarkMetrics,
    BenchmarkReport,
    BenchmarkResult,
)
from app.benchmark.semgrep_runner import (
    RULES_DIR,
    SemgrepRunner,
    parse_semgrep_json,
)
from app.benchmark.service import (
    BenchmarkService,
    InvalidFixtureNameError,
    UnknownFixtureError,
    to_benchmark_finding,
)

__all__ = [
    "BenchmarkComparison",
    "BenchmarkFinding",
    "BenchmarkMatcher",
    "BenchmarkMetrics",
    "BenchmarkReport",
    "BenchmarkResult",
    "BenchmarkService",
    "DEFAULT_TOLERANCE",
    "FIXTURE_GROUND_TRUTH",
    "GroundTruthCase",
    "InvalidFixtureNameError",
    "KNOWN_FIXTURES",
    "RULES_DIR",
    "SemgrepRunner",
    "UnknownFixtureError",
    "compute_metrics",
    "get_ground_truth",
    "parse_semgrep_json",
    "safe_cases",
    "to_benchmark_finding",
    "vulnerable_cases",
]