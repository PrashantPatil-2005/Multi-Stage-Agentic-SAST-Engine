"""Ground-truth metrics for the benchmark.

TP   = vulnerable ground-truth cases matched by the tool.
FP   = findings that matched a safe case or no case at all.
FN   = vulnerable ground-truth cases the tool missed.

precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * PR * RC / (PR + RC)

Zero denominators yield ``None`` (undefined) instead of misleading values.

These metrics are fixture-specific: they only measure agreement with the
controlled ground truth and are NOT a claim of real-world accuracy.
"""

from app.benchmark.ground_truth import (
    GroundTruthCase,
    safe_cases,
    vulnerable_cases,
)
from app.benchmark.matcher import BenchmarkMatcher
from app.benchmark.models import BenchmarkFinding, BenchmarkMetrics


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def compute_metrics(
    tool: str,
    findings: list[BenchmarkFinding],
    fixture: str,
    matcher: BenchmarkMatcher | None = None,
) -> BenchmarkMetrics:
    """Compute TP/FP/FN + precision/recall/F1 against the fixture ground truth."""
    matcher = matcher or BenchmarkMatcher()
    cases = vulnerable_cases(fixture) + safe_cases(fixture)

    matched_ids, false_positives = matcher.classify(findings, cases)
    true_positives = len(matched_ids)
    false_negatives = len(vulnerable_cases(fixture)) - true_positives
    false_positives_count = len(false_positives)

    precision = _ratio(true_positives, true_positives + false_positives_count)
    recall = _ratio(true_positives, true_positives + false_negatives)
    f1: float | None = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = _ratio(2 * precision * recall, precision + recall)

    return BenchmarkMetrics(
        tool=tool,
        true_positives=true_positives,
        false_positives=false_positives_count,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1=f1,
        total_findings=len(findings),
    )