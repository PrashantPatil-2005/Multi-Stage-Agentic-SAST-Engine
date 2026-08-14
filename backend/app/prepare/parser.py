"""Python AST parsing using the standard-library ``ast`` module.

Only ``ast.parse`` is used; repository code is never imported, compiled
or executed. The parser is pure and deterministic: same input, same output.
"""

import ast
import hashlib
import logging
from typing import Any

from app.core.contracts import (
    AssignmentInfo,
    CallInfo,
    ClassInfo,
    FunctionInfo,
    ImportInfo,
    ParseErrorInfo,
    SourceFile,
)

logger = logging.getLogger(__name__)

_UNPARSE_CAP = 200  # max chars for stringified expressions
_ARGS_CAP = 10  # max stored stringified call args per call


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _ast_to_dict(node: ast.AST) -> dict[str, Any]:
    """Serialize an AST node into a JSON-friendly dict."""
    out: dict[str, Any] = {"type": type(node).__name__}
    if hasattr(node, "lineno"):
        out["lineno"] = node.lineno
    for field_name, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            out[field_name] = _ast_to_dict(value)
        elif isinstance(value, list):
            out[field_name] = [
                _ast_to_dict(item) if isinstance(item, ast.AST) else item
                for item in value
            ]
        else:
            out[field_name] = value
    return out


def _value_kind(value: ast.AST | None) -> AssignmentInfo.model_fields["value_kind"]:  # type: ignore[attr-defined]
    if value is None:
        return "none"
    if isinstance(value, ast.Call):
        return "call"
    if isinstance(value, ast.Attribute):
        return "attribute"
    if isinstance(value, ast.Name):
        return "name"
    if isinstance(value, ast.Constant):
        return "constant"
    if isinstance(value, ast.BinOp):
        return "binary_op"
    if isinstance(value, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        return "collection"
    if isinstance(value, ast.Subscript):
        return "subscript"
    if isinstance(value, ast.Lambda):
        return "lambda"
    if isinstance(value, ast.IfExp):
        return "ifexp"
    return "other"


class _Collector:
    """Single-pass collector over a parsed AST, preserving source order."""

    def __init__(self, path: str) -> None:
        self._path = path
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.imports: list[ImportInfo] = []
        self.calls: list[CallInfo] = []
        self.assignments: list[AssignmentInfo] = []

    def run(self, tree: ast.AST) -> None:
        for child in ast.iter_child_nodes(tree):
            self._visit(child, class_stack=(), fn_stack=())

    def _visit(
        self,
        node: ast.AST,
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
    ) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.functions.append(self._function(node, class_stack, fn_stack))
            self._walk_children(node, class_stack, fn_stack + (node.name,))
        elif isinstance(node, ast.ClassDef):
            self.classes.append(self._class(node))
            self._walk_children(node, class_stack + (node.name,), fn_stack)
        elif isinstance(node, ast.Call):
            self.calls.append(self._call(node))
            self._walk_children(node, class_stack, fn_stack)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            self.assignments.append(self._assignment(node))
            self._walk_children(node, class_stack, fn_stack)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            self.imports.extend(self._import(node))
        else:
            self._walk_children(node, class_stack, fn_stack)

    def _walk_children(
        self,
        node: ast.AST,
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
    ) -> None:
        for child in ast.iter_child_nodes(node):
            self._visit(child, class_stack, fn_stack)

    def _function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        class_stack: tuple[str, ...],
        fn_stack: tuple[str, ...],
    ) -> FunctionInfo:
        args: list[str] = []
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            args.append(arg.arg)
        if node.args.vararg is not None:
            args.append("*" + node.args.vararg.arg)
        if node.args.kwarg is not None:
            args.append("**" + node.args.kwarg.arg)
        qualified = ".".join((*class_stack, *fn_stack, node.name))
        return FunctionInfo(
            name=node.name,
            qualified_name=qualified,
            file=self._path,
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            args=args,
            decorators=[_truncate(ast.unparse(d), _UNPARSE_CAP) for d in node.decorator_list],
            is_method=bool(class_stack) and not fn_stack,
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )

    def _class(self, node: ast.ClassDef) -> ClassInfo:
        methods = [
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        return ClassInfo(
            name=node.name,
            file=self._path,
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            bases=[_truncate(ast.unparse(b), _UNPARSE_CAP) for b in node.bases],
            decorators=[_truncate(ast.unparse(d), _UNPARSE_CAP) for d in node.decorator_list],
            methods=methods,
        )

    def _call(self, node: ast.Call) -> CallInfo:
        func = ast.unparse(node.func)
        args = [_truncate(ast.unparse(a), _UNPARSE_CAP) for a in node.args][:_ARGS_CAP]
        keywords = [k.arg for k in node.keywords if k.arg]
        is_method = isinstance(node.func, ast.Attribute) and not isinstance(
            node.func.value, ast.Name
        )
        return CallInfo(
            func=_truncate(func, _UNPARSE_CAP),
            args=args,
            num_args=len(node.args) + len(node.keywords),
            keywords=keywords,
            is_method_call=is_method,
            file=self._path,
            line=node.lineno,
        )

    def _assignment(self, node: ast.Assign | ast.AnnAssign | ast.AugAssign) -> AssignmentInfo:
        if isinstance(node, ast.Assign):
            targets = [_truncate(ast.unparse(t), _UNPARSE_CAP) for t in node.targets]
            value = node.value
        else:
            targets = [_truncate(ast.unparse(node.target), _UNPARSE_CAP)]
            value = node.value
        return AssignmentInfo(
            targets=targets,
            value_kind=_value_kind(value),
            value_expr=_truncate(ast.unparse(value), _UNPARSE_CAP) if value is not None else "",
            file=self._path,
            line=node.lineno,
        )

    def _import(self, node: ast.Import | ast.ImportFrom) -> list[ImportInfo]:
        if isinstance(node, ast.Import):
            return [
                ImportInfo(
                    module=alias.name,
                    name=alias.asname or alias.name.split(".")[0],
                    alias=alias.asname,
                    kind="import",
                    file=self._path,
                    line=node.lineno,
                )
                for alias in node.names
            ]
        module = node.module or ""
        return [
            ImportInfo(
                module=module,
                name=alias.name,
                alias=alias.asname,
                kind="import_star" if alias.name == "*" else "from_import",
                file=self._path,
                line=node.lineno,
            )
            for alias in node.names
        ]


class PythonASTParser:
    """Parses a Python source file into a :class:`SourceFile`."""

    def parse(self, path: str, source: str) -> SourceFile:
        """Parse ``source`` (repo-relative ``path``) without executing anything."""
        sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        line_count = len(source.splitlines())
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            logger.debug("syntax error in %s: %s", path, exc.msg)
            return SourceFile(
                path=path,
                source=source,
                sha256=sha256,
                line_count=line_count,
                ast=None,
                functions=[],
                classes=[],
                imports=[],
                calls=[],
                assignments=[],
                error=ParseErrorInfo(
                    lineno=exc.lineno or 0,
                    offset=exc.offset or 0,
                    message=exc.msg or str(exc),
                ),
            )
        collector = _Collector(path)
        try:
            collector.run(tree)
            ast_dict = _ast_to_dict(tree)
        except RecursionError:
            logger.warning("AST too deeply nested in %s; storing without AST", path)
            ast_dict = None
        return SourceFile(
            path=path,
            source=source,
            sha256=sha256,
            line_count=line_count,
            ast=ast_dict,
            functions=collector.functions,
            classes=collector.classes,
            imports=collector.imports,
            calls=collector.calls,
            assignments=collector.assignments,
        )
