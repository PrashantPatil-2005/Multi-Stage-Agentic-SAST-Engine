"""Scan rule abstraction.

A rule tells the shared taint engine:
  * which expressions are taint sources
  * which call sites are sinks (and of which kind)
  * how to detect sanitization at a sink
  * how to score confidence

Propagation, string construction and taint path building are shared engine
logic so every rule behaves consistently.
"""

import ast
from abc import ABC, abstractmethod
from typing import ClassVar

from app.scan.models import SinkRef, SourceRef, TaintStep


class ScanRule(ABC):
    vulnerability_type: ClassVar[str]
    severity: ClassVar[str]
    # Whether function parameters are treated as potential taint entry points.
    poison_params: ClassVar[bool] = True

    @abstractmethod
    def is_source(self, expr: ast.AST, file: str, source: str) -> SourceRef | None:
        """Return a SourceRef when ``expr`` is a user-controlled input."""

    @abstractmethod
    def match_sink(self, call: ast.Call, file: str, source: str) -> SinkRef | None:
        """Return a SinkRef when ``call`` is a dangerous sink invocation."""

    def is_sanitized(self, call: ast.Call, sink: SinkRef) -> bool:
        """True when the sink call neutralizes the tainted data (e.g. parameterized SQL)."""
        return False

    def confidence(self, path: list[TaintStep], source_kind: str) -> float:
        """Deterministic scanner confidence in [0, 1] (no LLM)."""
        return 0.7
