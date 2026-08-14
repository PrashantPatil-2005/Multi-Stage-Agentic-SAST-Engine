"""SSRF (Server-Side Request Forgery) rule.

Sources: same as SQL/command injection - Flask-style request objects plus
poisoned function parameters (shared logic in ``rules/common.py``).

Sinks: Python HTTP client APIs
  * requests.get / post / put / delete / patch / head / options / request
  * httpx.get / post / put / delete / patch / request
  * urllib.request.urlopen

URL argument handling:
  * ``requests.get(url)``            -> first positional argument
  * ``requests.request("GET", url)`` -> second positional argument
  * ``httpx.request("GET", url)``    -> second positional argument
  * ``urllib.request.urlopen(url)``  -> first positional argument
  * ``url=url`` keyword works everywhere

A finding is emitted only when the URL expression actually carries tainted
data. Constant URLs and constant URL variables are never flagged.

Deliberately NOT implemented in this MVP:
  * target classification (localhost / private IP / cloud metadata): the
    scanner only reports USER CONTROLLED INPUT -> HTTP REQUEST SINK; the
    rule is structured so classification can be added later.
  * actual network requests: the scanner is a pure AST analysis, it never
    executes or fetches anything from the analyzed repository.
"""

import ast
from typing import ClassVar

from app.scan.evidence import source_segment
from app.scan.models import SinkRef, SourceRef, TaintStep
from app.scan.rules import ScanRule
from app.scan.rules.common import request_source, taint_confidence

#: Recognized HTTP client calls: dotted function name -> sink kind.
HTTP_REQUEST_FUNCS = frozenset(
    {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.head",
        "requests.options",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.patch",
        "httpx.request",
        "urllib.request.urlopen",
    }
)


class SSRFRule(ScanRule):
    vulnerability_type: ClassVar[str] = "ssrf"
    severity: ClassVar[str] = "high"
    poison_params: ClassVar[bool] = True

    # ---------------------------------------------------------------- sources

    def is_source(self, expr: ast.AST, file: str, source: str) -> SourceRef | None:
        return request_source(expr, file, source)

    # ------------------------------------------------------------------ sinks

    def match_sink(self, call: ast.Call, file: str, source: str) -> SinkRef | None:
        func_name = ast.unparse(call.func)
        if func_name not in HTTP_REQUEST_FUNCS:
            return None
        if self.sink_expression(call) is None:
            return None
        return SinkRef(
            file=file,
            line=call.lineno,
            snippet=source_segment(source, call),
            kind="http_request",
        )

    # -------------------------------------------------------- URL argument

    def sink_expression(self, call: ast.Call) -> ast.AST | None:
        """Locate the URL argument of an HTTP call.

        Prefers the ``url=`` keyword; falls back to positional: the first
        positional for regular verbs, the second for ``*.request(method, url)``.
        """
        for keyword in call.keywords:
            if keyword.arg == "url":
                return keyword.value
        args = call.args
        func_name = ast.unparse(call.func)
        if func_name.endswith(".request"):
            return args[1] if len(args) >= 2 else None
        return args[0] if args else None

    # ------------------------------------------------------------- confidence

    def confidence(self, path: list[TaintStep], source_kind: str) -> float:
        return taint_confidence(path, source_kind)
