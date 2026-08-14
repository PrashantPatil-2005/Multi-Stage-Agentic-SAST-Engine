"""Shared logic for scan rules: request-object sources and confidence scoring.

Both the SQL injection and command injection rules treat Flask-style
``request`` objects as taint sources and score confidence identically, so
the logic lives here instead of being duplicated per rule.
"""

import ast

from app.scan.evidence import source_segment
from app.scan.models import SourceRef, TaintStep

#: Attributes of the Flask ``request`` object treated as user-controlled input.
REQUEST_ATTRS = frozenset({"args", "form", "values", "json", "cookies", "headers"})


def request_source(expr: ast.AST, file: str, source: str) -> SourceRef | None:
    """Recognize Flask-style request expressions as taint sources.

    Matches ``request.args``, ``request.json``, ``request.args[...]``,
    ``request.args.get(...)`` and the other REQUEST_ATTRS variants.
    """
    if isinstance(expr, ast.Attribute):
        if (
            isinstance(expr.value, ast.Name)
            and expr.value.id == "request"
            and expr.attr in REQUEST_ATTRS
        ):
            kind = "request_json" if expr.attr == "json" else "request_param"
            return SourceRef(
                file=file,
                line=expr.lineno,
                snippet=source_segment(source, expr),
                kind=kind,
            )
        return request_source(expr.value, file, source)
    if isinstance(expr, ast.Subscript):
        return request_source(expr.value, file, source)
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Attribute) and func.attr == "get":
            receiver = func.value
            if (
                isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name)
                and receiver.value.id == "request"
                and receiver.attr in REQUEST_ATTRS
            ):
                return SourceRef(
                    file=file,
                    line=expr.lineno,
                    snippet=source_segment(source, expr),
                    kind="request_param",
                )
        return None
    return None


def taint_confidence(path: list[TaintStep], source_kind: str) -> float:
    """Deterministic confidence (shared by all rules).

    * base 0.9 when the flow starts from an explicit request object
    * base 0.7 when the flow starts from a (poisoned) function parameter
    * minus 0.1 when the flow has >= 3 intermediate steps (uncertain chain)
    """
    base = 0.9 if source_kind.startswith("request") else 0.7
    intermediate = [
        s
        for s in path
        if s.step_type in ("assignment", "propagation", "string_construction")
    ]
    return round(base - (0.1 if len(intermediate) >= 3 else 0.0), 2)
