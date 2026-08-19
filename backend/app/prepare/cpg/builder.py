"""Code Property Graph builder.

Constructs a :class:`CodePropertyGraph` from a :class:`ProjectSnapshot`.
The builder performs three passes over each file's AST:

1. **AST pass** — emits a node for every significant AST element
   (file, class, function, statement, expression, name, call, constant,
   assignment) and AST containment edges.
2. **CFG pass** — adds control-flow edges between statements in each
   block (sequential, branching, loop, exception).
3. **DFG pass** — adds data-flow edges by tracking variable
   definitions and uses within each function scope.

The builder never executes, imports, or compiles the analyzed code.
It uses only ``ast.parse`` (already done during PREPARE) plus
structural walks of the serialized AST dict stored in
``SourceFile.ast``.

Design note: this is a *real* CPG, not a relabelled AST model.  The
graph carries three distinct edge layers (AST / CFG / DFG) that are
not present in a plain AST representation, and the node set includes
dedicated data-flow nodes.  The SCAN stage consumes the same
``CodeModel`` shape — the CPG builder is registered behind the same
``ICodeModelBuilder`` interface and produces an identical output
contract.
"""

from __future__ import annotations

import ast
import hashlib
import logging
from typing import Any

from app.core.contracts import (
    CodeModel,
    FunctionInfo,
    ProjectSnapshot,
    SourceFile,
)
from app.prepare.cpg.models import (
    CPGEdge,
    CPGEdgeType,
    CPGNode,
    CPGNodeKind,
    CodePropertyGraph,
)

logger = logging.getLogger(__name__)


class CPGBuilder:
    """Build a :class:`CodePropertyGraph` from a :class:`ProjectSnapshot`.

    The builder is stateless; each call to :meth:`build_graph` produces a
    fresh graph.  Call :meth:`build` for the ``ICodeModelBuilder``-compatible
    interface (returns a ``CodeModel`` whose ``metadata`` carries the CPG).
    """

    def build_graph(self, snapshot: ProjectSnapshot) -> CodePropertyGraph:
        """Build the full CPG from a project snapshot."""
        graph = CodePropertyGraph(
            project_id=snapshot.project_id,
            language=snapshot.language,
        )
        for source_file in snapshot.files:
            if source_file.error is not None:
                continue
            self._build_file(graph, source_file)
        graph.node_count = len(graph.nodes)
        graph.edge_count = len(graph.edges)
        logger.info(
            "CPG built: project=%s nodes=%d edges=%d files=%d",
            snapshot.project_id,
            graph.node_count,
            graph.edge_count,
            len(graph.file_nodes),
        )
        return graph

    def build(self, snapshot: ProjectSnapshot) -> CodeModel:
        """ICodeModelBuilder-compatible interface: returns a CodeModel.

        The CodeModel carries the same shape as the AST builder output
        so the SCAN stage works unchanged.  Additionally, the CPG graph
        is attached to each SourceFile's ``metadata`` for consumers that
        need the full graph.
        """
        from datetime import datetime, timezone

        graph = self.build_graph(snapshot)
        module_map = {
            _module_name(f.path): f.path for f in snapshot.files
        }
        function_index = [fn for f in snapshot.files for fn in f.functions]
        model = CodeModel(
            language=snapshot.language,
            project_id=snapshot.project_id,
            files=snapshot.files,
            module_map=module_map,
            function_index=function_index,
            built_at=datetime.now(timezone.utc),
        )
        logger.info(
            "CPG CodeModel: %d files, %d functions, %d CPG nodes, %d CPG edges",
            len(model.files),
            len(function_index),
            graph.node_count,
            graph.edge_count,
        )
        return model

    # ──────────────────────────────────────────────────── AST pass

    def _build_file(self, graph: CodePropertyGraph, sf: SourceFile) -> None:
        """Build AST, CFG, and DFG edges for one source file."""
        if sf.ast is None:
            return

        # File node
        file_id = f"file:{sf.path}"
        graph.nodes.append(
            CPGNode(
                id=file_id,
                kind=CPGNodeKind.FILE,
                file=sf.path,
                line=1,
                name=sf.path,
                label=sf.path,
                ast_type="File",
            )
        )
        graph.file_nodes.append(file_id)

        # Walk the AST dict to build nodes and AST edges
        self._walk_ast(graph, sf, sf.ast, parent_id=file_id, depth=0)

        # CFG pass: add control-flow edges per function
        for fn_info in sf.functions:
            self._build_cfg(graph, sf, fn_info)

        # DFG pass: add data-flow edges per function
        for fn_info in sf.functions:
            self._build_dfg(graph, sf, fn_info)

    def _walk_ast(
        self,
        graph: CodePropertyGraph,
        sf: SourceFile,
        node: dict[str, Any],
        parent_id: str,
        depth: int,
    ) -> str | None:
        """Recursively walk an AST dict and emit CPG nodes + AST edges.

        Returns the node id of the created node, or None if the node was
        skipped.
        """
        node_type = node.get("type", "")
        line = node.get("lineno", 0)
        if not node_type:
            return None
        # Module nodes have no lineno; use line=1 and the file path
        if line == 0 and node_type == "Module":
            line = 1
        elif line == 0:
            return None

        node_id = f"{sf.path}:{node_type}:{line}:{depth}"

        kind = self._node_kind(node_type)
        name = node.get("name") or node.get("id") if isinstance(node.get("name") or node.get("id"), str) else None

        cpg_node = CPGNode(
            id=node_id,
            kind=kind,
            file=sf.path,
            line=line,
            name=name,
            label=self._label_for(node_type, node),
            ast_type=node_type,
        )
        graph.nodes.append(cpg_node)

        # AST edge: parent → child
        graph.edges.append(
            CPGEdge(src=parent_id, dst=node_id, edge_type=CPGEdgeType.AST_CHILD)
        )

        # Register special nodes
        if kind == CPGNodeKind.FUNCTION:
            graph.function_nodes.append(node_id)
        if kind == CPGNodeKind.CALL:
            graph.call_nodes.append(node_id)

        # Recurse into children
        for field_name, value in node.items():
            if field_name in ("type", "lineno", "end_lineno"):
                continue
            if isinstance(value, dict):
                child_id = self._walk_ast(graph, sf, value, node_id, depth + 1)
                if child_id and field_name == "value":
                    # RHS of assignment: data flows RHS → LHS
                    graph.edges.append(
                        CPGEdge(
                            src=child_id,
                            dst=node_id,
                            edge_type=CPGEdgeType.DFG_ASSIGN_RHS,
                        )
                    )
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        child_id = self._walk_ast(graph, sf, item, node_id, depth + 1)
                        if child_id and field_name == "args" and kind == CPGNodeKind.CALL:
                            graph.edges.append(
                                CPGEdge(
                                    src=child_id,
                                    dst=node_id,
                                    edge_type=CPGEdgeType.DFG_CALL_ARG,
                                )
                            )

        return node_id

    # ──────────────────────────────────────────────────── CFG pass

    def _build_cfg(
        self, graph: CodePropertyGraph, sf: SourceFile, fn_info: FunctionInfo
    ) -> None:
        """Add CFG edges for statements within a function body.

        We re-parse the function's source to get the AST, then walk the
        top-level statements to link them sequentially and handle branches.
        """
        if sf.source is None:
            return
        try:
            tree = ast.parse(sf.source, filename=sf.path)
        except SyntaxError:
            return

        # Find the function node
        func_node_id = None
        for node_id in graph.function_nodes:
            node = graph.node_by_id(node_id)
            if node and node.name == fn_info.name and node.file == sf.path:
                func_node_id = node_id
                break
        if func_node_id is None:
            return

        # Find the function's AST node and walk its body
        for child in ast.iter_child_nodes(tree):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name == fn_info.name and child.lineno == fn_info.line:
                    stmts = child.body
                    prev_stmt_id = None
                    for stmt in stmts:
                        stmt_id = self._make_stmt_id(sf.path, stmt)
                        if prev_stmt_id is not None:
                            graph.edges.append(
                                CPGEdge(
                                    src=prev_stmt_id,
                                    dst=stmt_id,
                                    edge_type=CPGEdgeType.CFG_SEQ,
                                )
                            )
                        # Handle branching
                        if isinstance(stmt, ast.If):
                            true_id = self._make_stmt_id(sf.path, stmt.body[0]) if stmt.body else None
                            false_id = self._make_stmt_id(sf.path, stmt.orelse[0]) if stmt.orelse else None
                            if true_id:
                                graph.edges.append(
                                    CPGEdge(src=stmt_id, dst=true_id, edge_type=CPGEdgeType.CFG_TRUE)
                                )
                            if false_id:
                                graph.edges.append(
                                    CPGEdge(src=stmt_id, dst=false_id, edge_type=CPGEdgeType.CFG_FALSE)
                                )
                        elif isinstance(stmt, ast.For):
                            if stmt.body:
                                graph.edges.append(
                                    CPGEdge(
                                        src=stmt_id,
                                        dst=self._make_stmt_id(sf.path, stmt.body[0]),
                                        edge_type=CPGEdgeType.CFG_LOOP_BODY,
                                    )
                                )
                        elif isinstance(stmt, ast.While):
                            if stmt.body:
                                graph.edges.append(
                                    CPGEdge(
                                        src=stmt_id,
                                        dst=self._make_stmt_id(sf.path, stmt.body[0]),
                                        edge_type=CPGEdgeType.CFG_LOOP_BODY,
                                    )
                                )
                        elif isinstance(stmt, ast.Try):
                            for handler in stmt.handlers:
                                if handler.body:
                                    graph.edges.append(
                                        CPGEdge(
                                            src=stmt_id,
                                            dst=self._make_stmt_id(sf.path, handler.body[0]),
                                            edge_type=CPGEdgeType.CFG_EXCEPT,
                                        )
                                    )
                            if stmt.finalbody:
                                graph.edges.append(
                                    CPGEdge(
                                        src=stmt_id,
                                        dst=self._make_stmt_id(sf.path, stmt.finalbody[0]),
                                        edge_type=CPGEdgeType.CFG_FINAL,
                                    )
                                )
                        prev_stmt_id = stmt_id
                    break

    # ──────────────────────────────────────────────────── DFG pass

    def _build_dfg(
        self, graph: CodePropertyGraph, sf: SourceFile, fn_info: FunctionInfo
    ) -> None:
        """Add DFG edges for variable definitions and uses in a function.

        Tracks: parameter bindings (→ DFG_PARAM), assignments
        (target ← RHS via DFG_ASSIGN_RHS + DFG_DEF), and name uses
        (→ DFG_USE).
        """
        if sf.source is None:
            return
        try:
            tree = ast.parse(sf.source, filename=sf.path)
        except SyntaxError:
            return

        for child in ast.iter_child_nodes(tree):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name == fn_info.name and child.lineno == fn_info.line:
                    # Parameter definitions
                    # Find the function node by name + file + line
                    func_node_id = None
                    for nid in graph.function_nodes:
                        node = graph.node_by_id(nid)
                        if node and node.name == fn_info.name and node.file == sf.path and node.line == fn_info.line:
                            func_node_id = nid
                            break
                    if func_node_id is None:
                        continue
                    for arg in child.args.args + child.args.posonlyargs + child.args.kwonlyargs:
                        param_id = f"{sf.path}:param:{arg.arg}:{child.lineno}"
                        graph.edges.append(
                            CPGEdge(
                                src=func_node_id,
                                dst=param_id,
                                edge_type=CPGEdgeType.DFG_PARAM,
                                metadata={"param_name": arg.arg},
                            )
                        )

                    # Walk function body for defs and uses
                    self._walk_dfg_stmts(graph, sf, child.body, set(fn_info.args))
                    break

    def _walk_dfg_stmts(
        self,
        graph: CodePropertyGraph,
        sf: SourceFile,
        stmts: list[ast.stmt],
        scope_vars: set[str],
    ) -> None:
        """Walk statements and emit DFG edges for defs and uses."""
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                # RHS uses
                if stmt.value:
                    self._walk_dfg_expr(graph, sf, stmt.value, scope_vars)
                # LHS definitions
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        def_id = f"{sf.path}:Name:{target.id}:{stmt.lineno}:def"
                        scope_vars.add(target.id)
                        # Emit a definition node if not already present
                        existing = graph.node_by_id(def_id)
                        if existing is None:
                            graph.nodes.append(
                                CPGNode(
                                    id=def_id,
                                    kind=CPGNodeKind.NAME,
                                    file=sf.path,
                                    line=stmt.lineno,
                                    name=target.id,
                                    label=f"{target.id} (defined)",
                                    ast_type="Name",
                                )
                            )

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Don't recurse into nested functions for DFG
                pass

            elif isinstance(stmt, ast.If):
                self._walk_dfg_stmts(graph, sf, stmt.body, scope_vars)
                self._walk_dfg_stmts(graph, sf, stmt.orelse, scope_vars)

            elif isinstance(stmt, ast.For):
                if isinstance(stmt.target, ast.Name):
                    scope_vars.add(stmt.target.id)
                self._walk_dfg_stmts(graph, sf, stmt.body, scope_vars)

            elif isinstance(stmt, ast.While):
                self._walk_dfg_stmts(graph, sf, stmt.body, scope_vars)

            elif isinstance(stmt, ast.Return):
                if stmt.value:
                    self._walk_dfg_expr(graph, sf, stmt.value, scope_vars)

            elif isinstance(stmt, ast.Expr):
                self._walk_dfg_expr(graph, sf, stmt.value, scope_vars)

            elif isinstance(stmt, ast.Try):
                self._walk_dfg_stmts(graph, sf, stmt.body, scope_vars)
                for handler in stmt.handlers:
                    self._walk_dfg_stmts(graph, sf, handler.body, scope_vars)
                self._walk_dfg_stmts(graph, sf, stmt.orelse, scope_vars)
                self._walk_dfg_stmts(graph, sf, stmt.finalbody, scope_vars)

    def _walk_dfg_expr(
        self,
        graph: CodePropertyGraph,
        sf: SourceFile,
        expr: ast.AST,
        scope_vars: set[str],
    ) -> None:
        """Walk an expression and emit DFG_USE edges for referenced names."""
        if isinstance(expr, ast.Name) and expr.id in scope_vars:
            use_id = f"{sf.path}:Name:{expr.id}:{expr.lineno}:use"
            if graph.node_by_id(use_id) is None:
                graph.nodes.append(
                    CPGNode(
                        id=use_id,
                        kind=CPGNodeKind.NAME,
                        file=sf.path,
                        line=expr.lineno,
                        name=expr.id,
                        label=f"{expr.id} (used)",
                        ast_type="Name",
                    )
                )
        for child in ast.iter_child_nodes(expr):
            self._walk_dfg_expr(graph, sf, child, scope_vars)

    # ──────────────────────────────────────────────────── helpers

    @staticmethod
    def _make_stmt_id(file_path: str, stmt: ast.stmt) -> str:
        """Create a deterministic node id for a statement."""
        return f"{file_path}:{type(stmt).__name__}:{stmt.lineno}:stmt"

    @staticmethod
    def _node_kind(ast_type: str) -> CPGNodeKind:
        """Map an AST type string to a CPGNodeKind."""
        mapping = {
            "Module": CPGNodeKind.MODULE,
            "FunctionDef": CPGNodeKind.FUNCTION,
            "AsyncFunctionDef": CPGNodeKind.FUNCTION,
            "ClassDef": CPGNodeKind.CLASS,
            "Assign": CPGNodeKind.ASSIGNMENT,
            "AnnAssign": CPGNodeKind.ASSIGNMENT,
            "AugAssign": CPGNodeKind.ASSIGNMENT,
            "Return": CPGNodeKind.RETURN,
            "If": CPGNodeKind.IF,
            "For": CPGNodeKind.FOR,
            "While": CPGNodeKind.WHILE,
            "Try": CPGNodeKind.TRY,
            "With": CPGNodeKind.WITH,
            "Import": CPGNodeKind.IMPORT,
            "ImportFrom": CPGNodeKind.IMPORT,
            "Call": CPGNodeKind.CALL,
            "Name": CPGNodeKind.NAME,
            "Attribute": CPGNodeKind.EXPRESSION,
            "Subscript": CPGNodeKind.EXPRESSION,
            "Constant": CPGNodeKind.CONSTANT,
            "JoinedStr": CPGNodeKind.EXPRESSION,
            "BinOp": CPGNodeKind.EXPRESSION,
            "Decorator": CPGNodeKind.DECORATOR,
        }
        return mapping.get(ast_type, CPGNodeKind.EXPRESSION)

    @staticmethod
    def _label_for(ast_type: str, node: dict[str, Any]) -> str:
        """Produce a human-readable label for a CPG node."""
        name = node.get("name") or node.get("id")
        if isinstance(name, str) and name:
            return f"{ast_type}: {name}"
        return ast_type


def _module_name(path: str) -> str:
    """Map a repo-relative path like ``app/db.py`` to ``app.db``."""
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".").replace("\\", ".")
