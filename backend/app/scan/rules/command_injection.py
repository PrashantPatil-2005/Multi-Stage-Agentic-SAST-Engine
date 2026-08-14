"""Command injection rule.

Sources: same as SQL injection - Flask-style request objects plus poisoned
function parameters (shared logic in ``rules/common.py``).

Sinks: Python command execution APIs
  * os.system, os.popen
  * subprocess.run, subprocess.call, subprocess.Popen
  * subprocess.check_call, subprocess.check_output

The first positional argument of each call is the command. A finding is only
emitted when tainted data actually reaches that argument.

Deliberate safe cases:
  * list-form (argument vector) invocations such as
    ``subprocess.run(["ping", "-c", "1", host])`` are NOT flagged - the value
    is not parsed by a shell (see limitations in scan/README.md).
  * constant commands (``subprocess.run("ls -la")``) are NOT flagged.
  * ``shell=True`` alone is NOT a vulnerability; untrusted data reaching the
    command is the vulnerability.

Confidence: identical to the shared rule scoring (request 0.9 / param 0.7,
minus 0.1 for chains of >= 3 intermediate steps).
"""

import ast
from typing import ClassVar

from app.scan.evidence import source_segment
from app.scan.models import SinkRef, SourceRef, TaintStep
from app.scan.rules import ScanRule
from app.scan.rules.common import request_source, taint_confidence

#: Recognized command execution APIs: dotted function name -> sink kind.
COMMAND_SINKS = {
    "os.system": "os_system",
    "os.popen": "os_popen",
    "subprocess.run": "subprocess_run",
    "subprocess.call": "subprocess_call",
    "subprocess.Popen": "subprocess_popen",
    "subprocess.check_call": "subprocess_check_call",
    "subprocess.check_output": "subprocess_check_output",
}


class CommandInjectionRule(ScanRule):
    vulnerability_type: ClassVar[str] = "command_injection"
    severity: ClassVar[str] = "high"
    poison_params: ClassVar[bool] = True

    # ---------------------------------------------------------------- sources

    def is_source(self, expr: ast.AST, file: str, source: str) -> SourceRef | None:
        return request_source(expr, file, source)

    # ------------------------------------------------------------------ sinks

    def match_sink(self, call: ast.Call, file: str, source: str) -> SinkRef | None:
        func_name = ast.unparse(call.func)
        if func_name not in COMMAND_SINKS:
            return None
        if not call.args:
            return None
        # Argument-vector (list/tuple literal) invocation: no shell parsing of
        # the command string happens, so it is not flagged (documented).
        if isinstance(call.args[0], (ast.List, ast.Tuple)):
            return None
        return SinkRef(
            file=file,
            line=call.lineno,
            snippet=source_segment(source, call),
            kind="command_exec",
        )

    # ------------------------------------------------------------- confidence

    def confidence(self, path: list[TaintStep], source_kind: str) -> float:
        return taint_confidence(path, source_kind)
