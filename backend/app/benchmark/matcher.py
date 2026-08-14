"""Structural finding matching for the benchmark.

Tools report different line numbers, snippets and messages for the same
vulnerability, so exact IDs are never compared. Matching is greedy and
structural:

A benchmark finding A matches finding B when ALL of:

1. same file (basename),
2. same canonical vulnerability type,
3. line distance <= tolerance (default 3), OR the function names are equal
   when both tools identified one.

Ground-truth matching uses the same rules against a case's source/sink
lines and function.

The tolerance is deliberately small so unrelated findings are not merged.
"""

from app.benchmark.ground_truth import GroundTruthCase
from app.benchmark.models import BenchmarkFinding

DEFAULT_TOLERANCE = 3


class BenchmarkMatcher:
    def __init__(self, tolerance: int = DEFAULT_TOLERANCE) -> None:
        self._tolerance = tolerance

    @property
    def tolerance(self) -> int:
        return self._tolerance

    # ------------------------------------------------------------- matching

    def _same(self, a: BenchmarkFinding, b: BenchmarkFinding) -> bool:
        if a.file != b.file:
            return False
        if a.vulnerability_type != b.vulnerability_type:
            return False
        line_close = abs(a.line - b.line) <= self._tolerance
        func_equal = bool(a.function and b.function and a.function == b.function)
        return line_close or func_equal

    def matches_case(
        self, finding: BenchmarkFinding, case: GroundTruthCase
    ) -> bool:
        if finding.file != case.file:
            return False
        if finding.vulnerability_type != case.vulnerability_type:
            return False
        line_close = (
            abs(finding.line - case.source_line) <= self._tolerance
            or abs(finding.line - case.sink_line) <= self._tolerance
        )
        func_equal = bool(finding.function and finding.function == case.function)
        return line_close or func_equal

    # ----------------------------------------------------------- cross-tool

    def match_cross_tool(
        self, ours: list[BenchmarkFinding], theirs: list[BenchmarkFinding]
    ) -> tuple[list[BenchmarkFinding], list[BenchmarkFinding], list[BenchmarkFinding]]:
        """Greedy matching: returns (shared, ours_only, theirs_only)."""
        shared: list[BenchmarkFinding] = []
        ours_only: list[BenchmarkFinding] = []
        theirs_only: list[BenchmarkFinding] = []

        remaining = list(theirs)
        for finding in ours:
            partner = next(
                (t for t in remaining if self._same(finding, t)), None
            )
            if partner is None:
                ours_only.append(finding)
            else:
                shared.append(finding)
                remaining.remove(partner)
        theirs_only = remaining
        return shared, ours_only, theirs_only

    # ------------------------------------------------------------ ground truth

    def classify(
        self,
        findings: list[BenchmarkFinding],
        cases: list[GroundTruthCase],
    ) -> tuple[list[str], list[BenchmarkFinding]]:
        """Classify findings against ground truth.

        Returns (matched_case_ids, false_positives) where false_positives
        are findings that either matched a *safe* case or matched nothing
        (i.e. an undocumented finding). A vulnerable case is consumed by the
        first matching finding; extra findings on the same case are FPs.
        """
        vulnerable = [c for c in cases if c.expected_vulnerable]
        safe = [c for c in cases if not c.expected_vulnerable]

        matched_case_ids: list[str] = []
        false_positives: list[BenchmarkFinding] = []
        consumed_vulnerable = set()
        consumed_safe = set()

        for finding in findings:
            hit = next(
                (
                    c
                    for c in vulnerable
                    if c.case_id not in consumed_vulnerable
                    and self.matches_case(finding, c)
                ),
                None,
            )
            if hit is not None:
                consumed_vulnerable.add(hit.case_id)
                matched_case_ids.append(hit.case_id)
                continue
            safe_hit = next(
                (
                    c
                    for c in safe
                    if c.case_id not in consumed_safe
                    and self.matches_case(finding, c)
                ),
                None,
            )
            if safe_hit is not None:
                consumed_safe.add(safe_hit.case_id)
            false_positives.append(finding)

        return matched_case_ids, false_positives