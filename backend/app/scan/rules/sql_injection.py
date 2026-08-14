"""SQL injection rule.

Sources: Flask-style request objects (request.args / form / values / json /
cookies / headers) and - via poisoned parameters - function arguments.

Sinks: ``*.execute`` / ``*.executemany`` / ``*.executescript`` on recognizable
database objects (cursor, conn, connection, db, database, engine, session,
``self`` inside a database-like class).

Sanitization: a sink call that supplies query parameters (second positional
argument or ``parameters=``/``params=`` keyword) is parameterized and safe.

Confidence: shared rule scoring (see ``rules/common.py``) - request 0.9 /
param 0.7, minus 0.1 for chains of >= 3 intermediate steps.
"""

import ast
from typing import ClassVar

from app.scan.evidence import source_segment
from app.scan.models import SinkRef, SourceRef, TaintStep
from app.scan.rules import ScanRule
from app.scan.rules.common import request_source, taint_confidence

#: Object names (final attribute of the call receiver) treated as DB handles.
SQL_OBJECT_NAMES = frozenset(
    {
        "cursor",
        "curs",
        "cur",
        "conn",
        "con",
        "connection",
        "db",
        "database",
        "engine",
        "session",
        "handle",
    }
)

SQL_METHODS = frozenset({"execute", "executemany", "executescript"})


class SqlInjectionRule(ScanRule):
    vulnerability_type: ClassVar[str] = "sql_injection"
    severity: ClassVar[str] = "high"
    poison_params: ClassVar[bool] = True

    # ---------------------------------------------------------------- sources

    def is_source(self, expr: ast.AST, file: str, source: str) -> SourceRef | None:
        return request_source(expr, file, source)

    # ------------------------------------------------------------------ sinks

    def match_sink(self, call: ast.Call, file: str, source: str) -> SinkRef | None:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None
        if func.attr not in SQL_METHODS:
            return None
        receiver = ast.unparse(func.value)
        last = receiver.split(".")[-1]
        if receiver == "self" or last in SQL_OBJECT_NAMES:
            return SinkRef(
                file=file,
                line=call.lineno,
                snippet=source_segment(source, call),
                kind="sql_execute",
            )
        return None

    # ------------------------------------------------------------- sanitizers

    def is_sanitized(self, call: ast.Call, sink: SinkRef) -> bool:
        # Parameterized query: a non-None parameters argument makes the call safe.
        if len(call.args) >= 2:
            second = call.args[1]
            if not (isinstance(second, ast.Constant) and second.value is None):
                return True
        for keyword in call.keywords:
            if keyword.arg in ("parameters", "params"):
                value = keyword.value
                if not (isinstance(value, ast.Constant) and value.value is None):
                    return True
        return False

    # ------------------------------------------------------------- confidence

    def confidence(self, path: list[TaintStep], source_kind: str) -> float:
        return taint_confidence(path, source_kind)
