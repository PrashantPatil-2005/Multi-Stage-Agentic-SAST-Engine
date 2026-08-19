"""Deterministic line-anchored remediation patches.

Generates a :class:`RemediationProposal` for one finding and applies it to a
workspace copy of the repository. The transforms are intentionally
conservative and per-vulnerability-type:

* ``sql_injection``: parameterize a query argument — handles f-strings,
  string concatenation (``+``), and augmented assignment (``+=``).
  A genuine parameterization; only applied when the query structure can
  be safely decomposed into literal segments and variable placeholders.
* ``command_injection``: neutralize the shell path -
  ``subprocess.run(cmd, shell=True)`` -> ``subprocess.run(shlex.split(cmd))``
  (argument-vector form, documented safe) and ``os.system(cmd)`` ->
  ``os.system(shlex.quote(cmd))``; adds ``import shlex`` when missing.
* everything else (including ``ssrf``, where a correct fix depends on the
  intended allowlist): ``no_automatic_fix`` - nothing is ever patched and
  the human must remediate manually.

The patch is applied ONLY to the private workspace copy
(``workspace/projects/<id>/repo/``); the original source is never touched.
No patch is ever executed or validated against a live runtime.
"""

import ast
import logging

from app.remediation.models import RemediationProposal
from app.scan.models import CandidateFinding

logger = logging.getLogger(__name__)

#: Receivers for SQL sinks (mirrors the sql_injection rule's DB object names).
SQL_METHODS = frozenset({"execute", "executemany", "executescript"})
SUBPROCESS_SINKS = frozenset(
    {"subprocess.run", "subprocess.call", "subprocess.Popen",
     "subprocess.check_call", "subprocess.check_output"}
)
SHELL_STRING_SINKS = frozenset({"os.system", "os.popen"})


class PatchError(Exception):
    """Raised when a patch cannot be generated or applied."""


def _sink_lines(finding: CandidateFinding, source: str) -> tuple[int, str]:
    """Return (1-based line, exact line text) of the sink line."""
    lines = source.splitlines(keepends=True)
    if finding.sink.line < 1 or finding.sink.line > len(lines):
        raise PatchError(f"sink line {finding.sink.line} is outside the file")
    return finding.sink.line, lines[finding.sink.line - 1]


def _no_fix(finding: CandidateFinding, reason: str) -> RemediationProposal:
    snippet = finding.sink.snippet
    return RemediationProposal(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        file=finding.sink.file,
        line=finding.sink.line,
        strategy="no_automatic_fix",
        before=snippet,
        after=snippet,
        rationale=reason,
    )


def _sql_proposal(finding: CandidateFinding, source: str) -> RemediationProposal:
    """Parameterize ``obj.execute(f"... {x}")`` -> ``obj.execute("... ?", (x,))``.

    The f-string may be the direct sink argument or an intermediate variable
    (``query = f"..."`` followed by ``obj.execute(query)``); in both cases the
    interpolated values are moved into a parameter tuple so they can no longer
    alter the statement structure.
    """
    line_no, line_text = _sink_lines(finding, source)
    try:
        tree = ast.parse(source, filename=finding.sink.file)
    except SyntaxError as exc:
        return _no_fix(finding, f"file does not parse ({exc}); automatic fix unavailable")
    call = _find_call_at(tree, finding.sink.line)
    if call is None or not isinstance(call.func, ast.Attribute):
        return _no_fix(finding, "sink is not a recognizable SQL execute call")
    if call.func.attr not in SQL_METHODS:
        return _no_fix(finding, "sink method is not a SQL execute call")
    if not call.args:
        return _no_fix(finding, "sink call has no query argument")
    query_arg = call.args[0]

    # Strategy 1: direct f-string or assigned f-string variable.
    fstring_parts: list[str] | None = None
    fstring_params: list[str] | None = None

    if isinstance(query_arg, ast.JoinedStr) and any(
        isinstance(v, ast.FormattedValue) for v in query_arg.values
    ):
        fstring_parts, fstring_params = _decompose_fstring(query_arg)
    elif isinstance(query_arg, ast.Name):
        resolved_fstr = _resolve_assigned_fstring(tree, query_arg.id)
        if resolved_fstr is not None and any(
            isinstance(v, ast.FormattedValue) for v in resolved_fstr.values
        ):
            fstring_parts, fstring_params = _decompose_fstring(resolved_fstr)

    # Strategy 2: string concatenation (``+``) or augmented assignment (``+=``).
    concat_segments: list[tuple[str, str]] | None = None
    if fstring_parts is None and isinstance(query_arg, ast.Name):
        enclosing = _find_enclosing_function(tree, line_no)
        concat_segments = _resolve_assigned_concatenation(
            tree, query_arg.id, enclosing_fn=enclosing
        )

    if fstring_parts is not None and fstring_params is not None:
        new_query = "".join(fstring_parts)
        params: list[str] = fstring_params
    elif concat_segments is not None:
        # Build query template and param list from concatenation segments.
        query_parts: list[str] = []
        params = []
        for literal, var_expr in concat_segments:
            if literal == "?":
                query_parts.append("?")
                params.append(var_expr)
            else:
                query_parts.append(literal)
        new_query = "".join(query_parts)
    else:
        return _no_fix(
            finding,
            "query argument cannot be decomposed into a parameterizable "
            "form (f-string or string concatenation); automatic "
            "parameterization is not safe here",
        )

    new_args = [
        ast.Constant(value=new_query),
        ast.Tuple(elts=[ast.parse(p, mode="eval").body for p in params], ctx=ast.Load()),
    ]
    new_call = ast.copy_location(
        ast.Call(
            func=call.func,
            args=new_args,
            keywords=[k for k in call.keywords if k.arg not in ("parameters", "params")],
        ),
        call,
    )
    try:
        after = _render_statement_line(tree, call, new_call, line_no, line_text)
    except Exception as exc:  # noqa: BLE001
        return _no_fix(finding, f"rewritten sink cannot be rendered ({exc})")
    return RemediationProposal(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        file=finding.sink.file,
        line=line_no,
        strategy="parameterize_query",
        before=line_text.rstrip("\r\n"),
        after=after,
        rationale=(
            "Parameterized query: interpolated values are passed as query "
            "parameters instead of being embedded in the SQL text, so user "
            "input can no longer alter the statement structure."
        ),
    )


def _decompose_fstring(fstr: ast.JoinedStr) -> tuple[list[str], list[str]] | None:
    """Decompose an f-string into literal parts and parameter expressions.

    Returns ``(parts, params)`` where *parts* alternates between SQL literal
    segments and ``"?"`` placeholders, and *params* holds the unparsed
    variable expressions for each placeholder.  Returns ``None`` when the
    f-string cannot be safely decomposed.
    """
    parts: list[str] = []
    params: list[str] = []
    for value in fstr.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
        elif isinstance(value, ast.FormattedValue):
            try:
                params.append(ast.unparse(value.value))
            except Exception:  # noqa: BLE001
                return None
            parts.append("?")
        else:
            return None
    return parts, params


def _resolve_assigned_fstring(tree: ast.Module, name: str) -> ast.JoinedStr | None:
    """Resolve ``name = f"..."`` to the JoinedStr value (module scope scan)."""
    found: list[ast.JoinedStr] = []

    def walk(node: ast.AST) -> None:
        if isinstance(node, ast.Assign) and node.value is not None:
            targets = node.targets if isinstance(node.targets, list) else [node.target]
            if any(
                isinstance(t, ast.Name) and t.id == name for t in targets
            ) and isinstance(node.value, ast.JoinedStr):
                found.append(node.value)
        for child in ast.iter_child_nodes(node):
            walk(child)

    walk(tree)
    if len(found) != 1:
        return None
    return found[0]


def _collect_concat_parts(node: ast.AST) -> list[ast.AST]:
    """Recursively flatten a ``BinOp(Add)`` tree into its constituent parts.

    ``"a" + b + "c"`` → ``[Constant("a"), Name("b"), Constant("c")]``.
    Non-BinOp nodes are returned as-is.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _collect_concat_parts(node.left) + _collect_concat_parts(node.right)
    return [node]


def _resolve_assigned_concatenation(
    tree: ast.Module, name: str, *, enclosing_fn: ast.AST | None = None
) -> list[tuple[str, str]] | None:
    """Resolve all assignments to *name* built with string concatenation.

    Handles both ``name = ... + ...`` and ``name += ... + ...``.  When
    *enclosing_fn* is provided the search is scoped to that function's body
    (preventing cross-function false positives).  Returns a list of
    ``(literal_text, variable_expression)`` pairs representing the
    parameterised query segments, or ``None`` when the assignment cannot be
    safely decomposed.

    Each tuple is one of:

    * ``("literal_text", "")`` — a SQL literal segment.
    * ``("?", "variable_expression")`` — a parameter placeholder.

    The caller builds the new query string from the literal segments and the
    parameter list from the variable expressions.
    """
    assignments: list[ast.AST] = []
    search_root = enclosing_fn if enclosing_fn is not None else tree

    def _collect(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            # When scoping to a function, do not descend into nested
            # functions or classes — they have their own local scope.
            if enclosing_fn is not None and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if isinstance(child, ast.Assign) and child.value is not None:
                targets = (
                    child.targets if isinstance(child.targets, list) else [child.target]
                )
                if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                    assignments.append(child.value)
            elif isinstance(child, ast.AugAssign) and isinstance(child.target, ast.Name) and child.target.id == name:
                if isinstance(child.op, ast.Add):
                    assignments.append(child.value)
                else:
                    return  # non-Add augmented op: bail
            _collect(child)

    _collect(search_root)
    if not assignments:
        return None

    segments: list[tuple[str, str]] = []
    for value in assignments:
        parts = _collect_concat_parts(value)
        for part in parts:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                segments.append((part.value, ""))
            elif isinstance(part, (ast.Name, ast.Attribute, ast.Subscript)):
                try:
                    expr = ast.unparse(part)
                except Exception:  # noqa: BLE001
                    return None
                segments.append(("?", expr))
            else:
                # Non-literal, non-variable node (e.g. function call, complex
                # expression): we cannot safely parameterise this.
                return None
    return segments


def _render_statement_line(
    tree: ast.Module,
    old_call: ast.Call,
    new_call: ast.Call,
    line: int,
    line_text: str,
) -> str:
    """Render the statement containing ``old_call`` with ``new_call`` swapped in.

    Preserves the original line's leading indentation (``ast.unparse`` does
    not), so the rendered text can replace the anchored line verbatim.
    Falls back to unparsing just the call when no statement starts on the
    line (so the replacement is always anchored to the recorded line).
    """
    class _Swap(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call):
            if node is old_call:
                return new_call
            return self.generic_visit(node)

    statement = _find_statement_at(tree, line)
    if statement is None:
        return ast.unparse(new_call)
    indent = line_text[: len(line_text) - len(line_text.lstrip(" \t"))]
    rendered = ast.unparse(_Swap().visit(statement)).splitlines()
    if not rendered:
        return ast.unparse(new_call)
    return "\n".join(indent + rline for rline in rendered)


def _find_statement_at(tree: ast.Module, line: int) -> ast.AST | None:
    for node in ast.walk(tree):
        if not isinstance(
            node,
            (
                ast.Assign,
                ast.AnnAssign,
                ast.AugAssign,
                ast.Expr,
                ast.Return,
                ast.If,
                ast.For,
                ast.While,
                ast.With,
                ast.Try,
            ),
        ):
            continue
        if getattr(node, "lineno", None) == line:
            return node
    return None


def _cmd_proposal(finding: CandidateFinding, source: str) -> RemediationProposal:
    """Neutralize a shell-string command sink."""
    line_no, line_text = _sink_lines(finding, source)
    try:
        tree = ast.parse(source, filename=finding.sink.file)
    except SyntaxError as exc:
        return _no_fix(finding, f"file does not parse ({exc}); automatic fix unavailable")
    call = _find_call_at(tree, finding.sink.line)
    if call is None:
        return _no_fix(finding, "sink is not a recognizable command execution call")
    func_name = ast.unparse(call.func)
    if not call.args:
        return _no_fix(finding, "command call has no command argument")
    cmd = ast.unparse(call.args[0])
    if func_name in SUBPROCESS_SINKS:
        after_args = [ast.parse(f"shlex.split({cmd})", mode="eval").body]
        keywords = [
            k for k in call.keywords if not (k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True)
        ]
        strategy = "shell_argument_vector"
        rationale = (
            "Argument-vector form: the command is split into a list and "
            "passed without a shell, so user-controlled text is never "
            "interpreted as shell syntax."
        )
    elif func_name in SHELL_STRING_SINKS:
        after_args = [ast.parse(f"shlex.quote({cmd})", mode="eval").body]
        keywords = list(call.keywords)
        strategy = "shell_quote"
        rationale = (
            "Shell-quoted argument: user-controlled text is quoted so it "
            "cannot inject additional shell syntax into the command string."
        )
    else:
        return _no_fix(finding, "unrecognized command execution sink")
    new_call = ast.copy_location(
        ast.Call(func=call.func, args=after_args, keywords=keywords), call
    )
    try:
        after = _render_statement_line(tree, call, new_call, line_no, line_text)
    except Exception as exc:  # noqa: BLE001
        return _no_fix(finding, f"rewritten sink cannot be rendered ({exc})")
    needs_import = "import shlex" not in source and "from shlex" not in source
    return RemediationProposal(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        file=finding.sink.file,
        line=line_no,
        strategy=strategy,
        before=line_text.rstrip("\r\n"),
        after=after,
        import_to_add="import shlex" if needs_import else None,
        rationale=rationale,
    )


def _find_enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the function (or async function) that contains the given line."""
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= (node.end_lineno or node.lineno):
                if best is None or (node.lineno >= best.lineno):
                    best = node
    return best


def _find_call_at(tree: ast.Module, line: int) -> ast.Call | None:
    """Locate the Call node whose statement starts at ``line`` (or nearest)."""
    candidates: list[ast.Call] = []

    def walk(node: ast.AST) -> None:
        if isinstance(node, ast.Call) and node.lineno == line:
            candidates.append(node)
        for child in ast.iter_child_nodes(node):
            walk(child)

    walk(tree)
    if not candidates:
        return None
    # Prefer the outermost call (the sink itself, not a nested argument).
    return min(candidates, key=lambda c: sum(1 for _ in ast.walk(c)))


def build_proposal(finding: CandidateFinding, source: str) -> RemediationProposal:
    """Generate a deterministic proposal for one finding against ``source``."""
    vuln = finding.vulnerability_type
    if vuln == "sql_injection":
        return _sql_proposal(finding, source)
    if vuln == "command_injection":
        return _cmd_proposal(finding, source)
    return _no_fix(
        finding,
        f"no deterministic automatic fix is defined for {vuln}; "
        "manual remediation is required",
    )


def apply_proposal(proposal: RemediationProposal, source: str) -> str:
    """Apply the proposal to ``source``; returns the patched source.

    Raises :class:`PatchError` when the proposal cannot be applied (e.g. the
    file changed since the proposal was generated - the human must re-propose).
    """
    if proposal.strategy == "no_automatic_fix":
        raise PatchError("no automatic fix available for this finding")
    lines = source.splitlines(keepends=True)
    idx = proposal.line - 1
    if idx < 0 or idx >= len(lines):
        raise PatchError(f"proposal line {proposal.line} is outside the file")
    current = lines[idx].rstrip("\r\n")
    if current != proposal.before:
        raise PatchError(
            "source changed since the proposal was generated; "
            "generate a new proposal before applying"
        )
    start_indent = len(current) - len(current.lstrip(" \t"))
    end_idx = idx + 1
    while end_idx < len(lines):
        nxt = lines[end_idx].rstrip("\r\n")
        if not nxt:
            break
        nxt_indent = len(nxt) - len(nxt.lstrip(" \t"))
        if nxt_indent > start_indent:
            end_idx += 1
            continue
        if nxt_indent == start_indent and nxt.strip() in (")", "]", "}"):
            end_idx += 1
            break
        break
    new_lines = proposal.after.splitlines(keepends=True)
    if new_lines and not new_lines[-1].endswith(("\n", "\r")):
        new_lines[-1] += "\n"
    lines[idx:end_idx] = new_lines
    new_source = "".join(lines)
    if proposal.import_to_add is not None:
        new_source = _insert_import(new_source, proposal.import_to_add)
    # Sanity: the patched file must still parse.
    try:
        ast.parse(new_source, filename=proposal.file)
    except SyntaxError as exc:
        raise PatchError(f"patched source does not parse ({exc}); fix not applied") from exc
    return new_source


def _insert_import(source: str, import_line: str) -> str:
    """Insert ``import_line`` after the module docstring (or at the top)."""
    try:
        tree = ast.parse(source, filename="<patch>")
    except SyntaxError:
        return source
    insert_at = 0
    if tree.body and isinstance(tree.body[0], ast.Expr):
        value = tree.body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            insert_at = value.end_lineno  # type: ignore[attr-defined]
    lines = source.splitlines(keepends=True)
    lines.insert(insert_at, import_line + "\n")
    return "".join(lines)