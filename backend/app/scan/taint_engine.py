"""Deterministic taint engine (SCAN stage).

Intra-procedural, forward, statement-order taint propagation per function,
with limited control-flow handling (branches are merged via union of tainted
variables, which is a sound over-approximation).

The engine is rule-agnostic: sources, sinks and sanitizers come from a
``ScanRule``; propagation, string construction and taint path building are
shared logic.

Taint model: a map ``variable name -> _Taint`` where ``_Taint`` carries the
provenance (list of TaintSteps) of how the value became tainted plus the
kind of the originating source. Every propagated value therefore keeps a
full human-readable path back to its source.

Deliberately NOT implemented yet (documented in scan/README.md):
  * cross-function resolution via FunctionSummary (only recorded)
  * object/container field-sensitive tracking
  * aliasing through function arguments
"""

import ast
import hashlib
import logging
from dataclasses import dataclass, field

from app.core.contracts import SourceFile
from app.scan.evidence import EvidenceBuilder, line_text
from app.scan.models import CandidateFinding, FunctionSummary, SinkRef, TaintStep
from app.scan.rules import ScanRule

logger = logging.getLogger(__name__)


@dataclass
class _Taint:
    steps: list[TaintStep]
    source_kind: str


@dataclass
class _FnSummary:
    qualified_name: str
    line: int
    sinks: list[SinkRef] = field(default_factory=list)
    tainted_params: set[str] = field(default_factory=set)
    returns_taint: bool = False


class _FileContext:
    def __init__(self, rule: ScanRule, code_file: SourceFile, project_id: str) -> None:
        self.rule = rule
        self.project_id = project_id
        self.file = code_file.path
        self.source = code_file.source
        self.findings: list[CandidateFinding] = []
        self.summaries: list[FunctionSummary] = []
        self.evidence = EvidenceBuilder()


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = fn.args
    names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return [n for n in names if n not in ("self", "cls")]


def _collect_calls(node: ast.AST | None) -> list[ast.Call]:
    """Collect call nodes in source order, skipping nested function bodies."""
    out: list[ast.Call] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Call):
            out.append(n)
        for child in ast.iter_child_nodes(n):
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                continue
            walk(child)

    if node is not None:
        walk(node)
    return out


def _merge(parts: list[_Taint]) -> list[TaintStep]:
    """Concatenate provenance lists, deduplicating identical steps in order."""
    steps: list[TaintStep] = []
    seen: set[tuple] = set()
    for part in parts:
        for step in part.steps:
            key = (step.step_type, step.file, step.line, step.snippet)
            if key not in seen:
                seen.add(key)
                steps.append(step)
    return steps


def _kind(parts: list[_Taint]) -> str:
    for part in parts:
        if part.source_kind.startswith("request"):
            return part.source_kind
    return parts[0].source_kind


class TaintEngine:
    def __init__(self, rule: ScanRule, project_id: str = "") -> None:
        self._rule = rule
        self._project_id = project_id

    # ---------------------------------------------------------------- public

    def analyze_file(
        self, code_file: SourceFile
    ) -> tuple[list[CandidateFinding], list[FunctionSummary]]:
        """Analyze one Python file; returns (findings, function summaries)."""
        if code_file.error is not None:
            logger.debug("scan: skipping %s (parse error)", code_file.path)
            return [], []
        tree = ast.parse(code_file.source, filename=code_file.path)
        ctx = _FileContext(self._rule, code_file, self._project_id)
        self._analyze_block(ctx, tree.body, tainted={}, class_stack=(), fn_stack=(), summary=None)
        return ctx.findings, ctx.summaries

    # ----------------------------------------------------------- block walk

    def _analyze_block(
        self,
        ctx: _FileContext,
        stmts: list[ast.stmt],
        tainted: dict[str, _Taint],
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
        summary: _FnSummary | None,
    ) -> dict[str, _Taint]:
        tainted = dict(tainted)
        for stmt in stmts:
            tainted = self._apply_stmt(ctx, stmt, tainted, class_stack, fn_stack, summary)
        return tainted

    def _apply_stmt(
        self,
        ctx: _FileContext,
        stmt: ast.stmt,
        tainted: dict[str, _Taint],
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
        summary: _FnSummary | None,
    ) -> dict[str, _Taint]:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return self._apply_assign(ctx, stmt, tainted, summary)

        if isinstance(stmt, (ast.If, ast.While)):
            self._check_sinks(ctx, stmt.test, tainted, summary)
            merged = self._analyze_block(ctx, stmt.body, tainted, class_stack, fn_stack, summary)
            merged.update(
                self._analyze_block(ctx, stmt.orelse, tainted, class_stack, fn_stack, summary)
            )
            tainted.update(merged)
            return tainted

        if isinstance(stmt, ast.For):
            self._check_sinks(ctx, stmt.iter, tainted, summary)
            iter_taint = self._taint_of(ctx, stmt.iter, tainted)
            targets = stmt.target.elts if isinstance(stmt.target, ast.Tuple) else [stmt.target]
            if iter_taint is not None:
                for target in targets:
                    if isinstance(target, ast.Name):
                        tainted[target.id] = _Taint(
                            steps=iter_taint.steps + [self._propagation_step(ctx, stmt)],
                            source_kind=iter_taint.source_kind,
                        )
            merged = self._analyze_block(ctx, stmt.body, tainted, class_stack, fn_stack, summary)
            merged.update(
                self._analyze_block(ctx, stmt.orelse, tainted, class_stack, fn_stack, summary)
            )
            tainted.update(merged)
            return tainted

        if isinstance(stmt, ast.Try):
            blocks = [stmt.body, stmt.orelse, stmt.finalbody]
            blocks += [handler.body for handler in stmt.handlers]
            for block in blocks:
                tainted.update(
                    self._analyze_block(ctx, block, tainted, class_stack, fn_stack, summary)
                )
            return tainted

        if isinstance(stmt, ast.With):
            tainted.update(
                self._analyze_block(ctx, stmt.body, tainted, class_stack, fn_stack, summary)
            )
            return tainted

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._analyze_function(ctx, stmt, class_stack, fn_stack)
            return tainted

        if isinstance(stmt, ast.ClassDef):
            self._analyze_block(ctx, stmt.body, tainted={}, class_stack=class_stack + (stmt.name,), fn_stack=fn_stack, summary=None)
            return tainted

        if isinstance(stmt, ast.Expr):
            self._check_sinks(ctx, stmt.value, tainted, summary)
            return tainted

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._check_sinks(ctx, stmt.value, tainted, summary)
                if summary is not None and self._taint_of(ctx, stmt.value, tainted) is not None:
                    summary.returns_taint = True
            return tainted

        return tainted

    # ----------------------------------------------------------- assignments

    def _apply_assign(
        self,
        ctx: _FileContext,
        stmt: ast.Assign | ast.AnnAssign | ast.AugAssign,
        tainted: dict[str, _Taint],
        summary: _FnSummary | None,
    ) -> dict[str, _Taint]:
        if isinstance(stmt, ast.AugAssign):
            self._check_sinks(ctx, stmt.value, tainted, summary)
            target_t = tainted.get(stmt.target.id) if isinstance(stmt.target, ast.Name) else None
            value_t = self._taint_of(ctx, stmt.value, tainted)
            if isinstance(stmt.target, ast.Name) and (target_t is not None or value_t is not None):
                base = target_t if target_t is not None else value_t
                assert base is not None
                tainted[stmt.target.id] = _Taint(
                    steps=base.steps + [self._propagation_step(ctx, stmt)],
                    source_kind=base.source_kind,
                )
            return tainted

        if isinstance(stmt, ast.AnnAssign) and stmt.value is None:
            return tainted

        value = stmt.value
        assert value is not None
        self._check_sinks(ctx, value, tainted, summary)

        value_t = self._taint_of(ctx, value, tainted)
        if value_t is None:
            return tainted

        # Assignment step: appended only when the RHS is a raw source or a
        # plain name copy (string construction steps already carry the line).
        is_source_rhs = (
            isinstance(value, (ast.Call, ast.Attribute, ast.Subscript))
            and self._rule.is_source(value, ctx.file, ctx.source) is not None
        )
        steps = list(value_t.steps)
        if is_source_rhs or isinstance(value, ast.Name):
            steps = steps + [
                TaintStep(
                    step_type="assignment",
                    file=ctx.file,
                    line=stmt.lineno,
                    snippet=line_text(ctx.source, stmt.lineno),
                )
            ]
        for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
            if isinstance(target, ast.Name):
                tainted[target.id] = _Taint(steps=steps, source_kind=value_t.source_kind)
        return tainted

    # --------------------------------------------------------------- sources

    def _taint_of(
        self,
        ctx: _FileContext,
        expr: ast.AST | None,
        tainted: dict[str, _Taint],
    ) -> _Taint | None:
        if expr is None or isinstance(expr, ast.Constant):
            return None

        if isinstance(expr, ast.Name):
            return tainted.get(expr.id)

        if isinstance(expr, (ast.Call, ast.Attribute, ast.Subscript)):
            source_ref = self._rule.is_source(expr, ctx.file, ctx.source)
            if source_ref is not None:
                return _Taint(
                    steps=[
                        TaintStep(
                            step_type="source",
                            file=ctx.file,
                            line=expr.lineno,
                            snippet=source_ref.snippet,
                        )
                    ],
                    source_kind=source_ref.kind,
                )

        if isinstance(expr, ast.JoinedStr):
            parts = [
                self._taint_of(ctx, value.value, tainted)
                for value in expr.values
                if isinstance(value, ast.FormattedValue)
            ]
            parts = [p for p in parts if p is not None]
            if not parts:
                return None
            return _Taint(
                steps=_merge(parts) + [self._string_step(ctx, expr)],
                source_kind=_kind(parts),
            )

        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            left = self._taint_of(ctx, expr.left, tainted)
            right = self._taint_of(ctx, expr.right, tainted)
            parts = [p for p in (left, right) if p is not None]
            if not parts:
                return None
            return _Taint(
                steps=_merge(parts) + [self._string_step(ctx, expr)],
                source_kind=_kind(parts),
            )

        if isinstance(expr, ast.Call):
            func = expr.func
            if isinstance(func, ast.Name) and func.id in ("str", "repr", "bytes") and expr.args:
                inner = self._taint_of(ctx, expr.args[0], tainted)
                if inner is None:
                    return None
                return _Taint(
                    steps=inner.steps + [self._propagation_step(ctx, expr)],
                    source_kind=inner.source_kind,
                )
            if isinstance(func, ast.Attribute) and func.attr == "format":
                candidates = [self._taint_of(ctx, func.value, tainted)]
                candidates += [self._taint_of(ctx, a, tainted) for a in expr.args]
                parts = [p for p in candidates if p is not None]
                if not parts:
                    return None
                return _Taint(
                    steps=_merge(parts) + [self._string_step(ctx, expr)],
                    source_kind=_kind(parts),
                )
            return None

        if isinstance(expr, ast.Attribute):
            base = self._taint_of(ctx, expr.value, tainted)
            if base is None:
                return None
            return _Taint(
                steps=base.steps + [self._propagation_step(ctx, expr)],
                source_kind=base.source_kind,
            )

        if isinstance(expr, ast.Subscript):
            base = self._taint_of(ctx, expr.value, tainted)
            if base is None:
                return None
            return _Taint(
                steps=base.steps + [self._propagation_step(ctx, expr)],
                source_kind=base.source_kind,
            )

        if isinstance(expr, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            items: list = expr.elts if not isinstance(expr, ast.Dict) else list(expr.keys) + list(expr.values)
            parts = [p for p in (self._taint_of(ctx, i, tainted) for i in items) if p is not None]
            if not parts:
                return None
            return _Taint(
                steps=_merge(parts) + [self._propagation_step(ctx, expr)],
                source_kind=_kind(parts),
            )

        if isinstance(expr, ast.IfExp):
            parts = [
                self._taint_of(ctx, expr.test, tainted),
                self._taint_of(ctx, expr.body, tainted),
                self._taint_of(ctx, expr.orelse, tainted),
            ]
            parts = [p for p in parts if p is not None]
            if not parts:
                return None
            return _Taint(
                steps=_merge(parts) + [self._propagation_step(ctx, expr)],
                source_kind=_kind(parts),
            )

        return None

    # ------------------------------------------------------------------ sink

    def _check_sinks(
        self,
        ctx: _FileContext,
        node: ast.AST | None,
        tainted: dict[str, _Taint],
        summary: _FnSummary | None = None,
    ) -> None:
        for call in _collect_calls(node):
            sink = self._rule.match_sink(call, ctx.file, ctx.source)
            if sink is None:
                continue
            if self._rule.is_sanitized(call, sink):
                logger.debug("sanitized sink skipped at %s:%d", ctx.file, sink.line)
                continue
            target = self._rule.sink_expression(call)
            if target is None:
                continue
            taint = self._taint_of(ctx, target, tainted)
            if taint is None:
                continue
            if summary is not None:
                summary.sinks.append(sink)
            self._emit_finding(ctx, sink, taint)

    def _emit_finding(
        self, ctx: _FileContext, sink: SinkRef, taint: _Taint
    ) -> None:
        path = taint.steps + [
            TaintStep(
                step_type="sink",
                file=ctx.file,
                line=sink.line,
                snippet=sink.snippet,
            )
        ]
        first = path[0]
        source_ref = _source_ref_from_step(first, taint.source_kind)
        confidence = self._rule.confidence(path, taint.source_kind)
        evidence = ctx.evidence.build(
            ctx.source,
            source_ref,
            sink,
            path,
            ["no sanitizer observed at sink"],
        )
        finding_id = hashlib.sha256(
            f"{ctx.project_id}|{self._rule.vulnerability_type}|{ctx.file}|{source_ref.line}|{sink.line}".encode()
        ).hexdigest()
        finding = CandidateFinding(
            id=finding_id,
            vulnerability_type=self._rule.vulnerability_type,
            severity=self._rule.severity,
            confidence=confidence,
            source=source_ref,
            sink=sink,
            taint_path=path,
            evidence=evidence,
        )
        ctx.findings.append(finding)
        logger.info(
            "finding: %s source=%s:%d sink=%s:%d confidence=%.2f",
            self._rule.vulnerability_type,
            ctx.file,
            source_ref.line,
            ctx.file,
            sink.line,
            confidence,
        )

    # -------------------------------------------------------------- functions

    def _analyze_function(
        self,
        ctx: _FileContext,
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
    ) -> None:
        qualified = ".".join((*class_stack, *fn_stack, fn.name))
        summary = _FnSummary(qualified_name=qualified, line=fn.lineno)
        tainted: dict[str, _Taint] = {}
        def_line = line_text(ctx.source, fn.lineno)
        if self._rule.poison_params:
            for name in _param_names(fn):
                tainted[name] = _Taint(
                    steps=[
                        TaintStep(
                            step_type="source",
                            file=ctx.file,
                            line=fn.lineno,
                            snippet=def_line,
                        )
                    ],
                    source_kind="function_param",
                )
        self._analyze_block(
            ctx, fn.body, tainted, class_stack, fn_stack + (fn.name,), summary
        )
        summary.tainted_params = {name for name in _param_names(fn) if name in tainted}
        ctx.summaries.append(
            FunctionSummary(
                qualified_name=qualified,
                file=ctx.file,
                line=fn.lineno,
                tainted_params=sorted(summary.tainted_params),
                sinks=summary.sinks,
                returns_taint=summary.returns_taint,
            )
        )
        if summary.sinks:
            logger.debug(
                "summary: %s sinks=%d tainted_params=%s", qualified, len(summary.sinks), sorted(summary.tainted_params)
            )

    # --------------------------------------------------------------- helpers

    def _string_step(self, ctx: _FileContext, expr: ast.AST) -> TaintStep:
        return TaintStep(
            step_type="string_construction",
            file=ctx.file,
            line=expr.lineno,
            snippet=line_text(ctx.source, expr.lineno),
        )

    def _propagation_step(self, ctx: _FileContext, expr: ast.AST) -> TaintStep:
        return TaintStep(
            step_type="propagation",
            file=ctx.file,
            line=expr.lineno,
            snippet=line_text(ctx.source, expr.lineno),
        )


def _source_ref_from_step(step: TaintStep, source_kind: str):
    from app.scan.models import SourceRef

    return SourceRef(
        file=step.file, line=step.line, snippet=step.snippet, kind=source_kind
    )
