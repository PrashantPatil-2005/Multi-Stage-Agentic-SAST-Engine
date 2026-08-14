"""ScanService: SCAN stage entry point.

Consumes a ``CodeModel`` (from PREPARE) and returns a ``ScanReport`` with
candidate findings. Deterministic: the same code model always yields the
same findings (stable ids, stable ordering).

Not connected to the API yet; designed to be directly testable.
"""

import logging
from datetime import datetime, timezone
from uuid import uuid4

from app.core.contracts import CodeModel
from app.scan.models import CandidateFinding, FunctionSummary, ScanReport, ScanSummary
from app.scan.rules import ScanRule
from app.scan.rules.command_injection import CommandInjectionRule
from app.scan.rules.sql_injection import SqlInjectionRule
from app.scan.taint_engine import TaintEngine

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, rules: list[ScanRule] | None = None) -> None:
        self._rules = rules if rules is not None else [SqlInjectionRule(), CommandInjectionRule()]

    def scan(self, code_model: CodeModel) -> ScanReport:
        findings: list[CandidateFinding] = []
        summaries: list[FunctionSummary] = []

        for rule in self._rules:
            engine = TaintEngine(rule)
            for code_file in code_model.files:
                file_findings, file_summaries = engine.analyze_file(code_file)
                findings.extend(file_findings)
                summaries.extend(file_summaries)

        findings.sort(key=lambda f: (f.sink.file, f.sink.line, f.source.line))
        summaries = self._merge_summaries(summaries)

        by_type: dict[str, int] = {}
        for finding in findings:
            by_type[finding.vulnerability_type] = (
                by_type.get(finding.vulnerability_type, 0) + 1
            )

        report = ScanReport(
            id=uuid4().hex,
            created_at=datetime.now(timezone.utc),
            scanned_file_count=len(code_model.files),
            findings=findings,
            function_summaries=summaries,
            summary=ScanSummary(total=len(findings), by_type=by_type),
        )
        logger.info(
            "SCAN complete: %d findings across %d files (%s)",
            len(findings),
            len(code_model.files),
            by_type,
        )
        return report

    @staticmethod
    def _merge_summaries(summaries: list[FunctionSummary]) -> list[FunctionSummary]:
        """Merge per-rule observations for the same function.

        Each rule runs its own TaintEngine, so the same function is summarized
        once per rule; combine them so a single FunctionSummary carries every
        rule's observations.
        """
        merged: dict[tuple[str, int, str], FunctionSummary] = {}
        for s in summaries:
            key = (s.file, s.line, s.qualified_name)
            prev = merged.get(key)
            if prev is None:
                merged[key] = s
                continue
            merged[key] = FunctionSummary(
                qualified_name=s.qualified_name,
                file=s.file,
                line=s.line,
                tainted_params=sorted(set(prev.tainted_params) | set(s.tainted_params)),
                sinks=prev.sinks + s.sinks,
                returns_taint=prev.returns_taint or s.returns_taint,
            )
        return sorted(merged.values(), key=lambda s: (s.file, s.line, s.qualified_name))
