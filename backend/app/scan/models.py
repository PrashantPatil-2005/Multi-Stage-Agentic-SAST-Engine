"""SCAN stage output contracts.

A :class:`CandidateFinding` is the unit produced by the taint engine for one
source -> propagation -> sink flow. It is intentionally consistent with the
finding schema in ARCHITECTURE.md.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class SourceRef(BaseModel):
    file: str
    line: int
    snippet: str
    kind: str  # e.g. "request_param", "request_json", "function_param"


class SinkRef(BaseModel):
    file: str
    line: int
    snippet: str
    kind: str  # e.g. "sql_execute"


class TaintStep(BaseModel):
    file: str
    line: int
    snippet: str
    step_type: Literal[
        "source", "assignment", "propagation", "string_construction", "sink"
    ]


class Evidence(BaseModel):
    """Evidence is built exclusively from the actual parsed source."""

    source_snippet: str
    sink_snippet: str
    taint_path: list[TaintStep]
    relevant_lines: list[int]
    sanitizer_observations: list[str]


class CandidateFinding(BaseModel):
    id: str
    vulnerability_type: str
    severity: str
    confidence: float
    status: Literal["candidate"] = "candidate"
    source: SourceRef
    sink: SinkRef
    taint_path: list[TaintStep]
    evidence: Evidence


class FunctionSummary(BaseModel):
    """Seed of the cross-function abstraction.

    Currently only reflects intra-procedural observations; it is not yet
    consumed for inter-procedural resolution (see scan/README.md).
    """

    qualified_name: str
    file: str
    line: int
    tainted_params: list[str]
    sinks: list[SinkRef]
    returns_taint: bool


class ScanSummary(BaseModel):
    total: int
    by_type: dict[str, int]


class ScanReport(BaseModel):
    id: str
    created_at: datetime
    scanned_file_count: int
    findings: list[CandidateFinding]
    function_summaries: list[FunctionSummary]
    summary: ScanSummary
