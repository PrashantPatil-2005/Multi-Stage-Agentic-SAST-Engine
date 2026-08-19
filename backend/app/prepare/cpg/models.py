"""Code Property Graph data models.

A CPG is a labeled, directed graph with typed nodes and typed edges.
Three edge layers are supported:

* ``AST`` — structural parent→child (file → function → block → expression)
* ``CFG`` — control-flow between statements (sequential, true-branch,
  false-branch, exception-handler)
* ``DFG`` — data-flow definition→use links (assignment, parameter
  binding, return value)

Node kinds mirror the Python AST structure at a level of granularity
useful for taint analysis: file, module, class, function, block,
statement, expression, name (identifier), call, constant, and
assignment.

All models are Pydantic-compatible dicts (plain dataclasses for
lightweight construction); they serialize to JSON via ``model_dump``.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CPGNodeKind(str, Enum):
    """Kinds of CPG nodes."""

    FILE = "file"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    BLOCK = "block"
    STATEMENT = "statement"
    EXPRESSION = "expression"
    NAME = "name"
    CALL = "call"
    CONSTANT = "constant"
    ASSIGNMENT = "assignment"
    RETURN = "return"
    IF = "if"
    FOR = "for"
    WHILE = "while"
    TRY = "try"
    WITH = "with"
    IMPORT = "import"
    DECORATOR = "decorator"


class CPGEdgeType(str, Enum):
    """Kinds of CPG edges."""

    # AST edges: structural containment
    AST_CHILD = "ast_child"
    AST_FILE = "ast_file"
    AST_CLASS = "ast_class"
    AST_FUNCTION = "ast_function"
    AST_BODY = "ast_body"

    # CFG edges: control flow
    CFG_SEQ = "cfg_seq"  # sequential next statement
    CFG_TRUE = "cfg_true"  # true branch
    CFG_FALSE = "cfg_false"  # false branch
    CFG_LOOP_BODY = "cfg_loop_body"
    CFG_LOOP_NEXT = "cfg_loop_next"
    CFG_EXCEPT = "cfg_except"
    CFG_FINAL = "cfg_final"

    # DFG edges: data flow
    DFG_DEF = "dfg_def"  # variable defined here
    DFG_USE = "dfg_use"  # variable used here
    DFG_PARAM = "dfg_param"  # function parameter binding
    DFG_RETURN = "dfg_return"  # return value flow
    DFG_CALL_ARG = "dfg_call_arg"  # argument passed to callee
    DFG_CALL_RESULT = "dfg_call_result"  # return value from callee
    DFG_ASSIGN_RHS = "dfg_assign_rhs"  # RHS of assignment flows to LHS


class CPGNode(BaseModel):
    """A node in the Code Property Graph."""

    id: str  # unique within the graph, e.g. "file:app.py:12"
    kind: CPGNodeKind
    file: str  # repo-relative file path
    line: int
    end_line: int | None = None
    name: str | None = None  # function/class/variable name
    label: str | None = None  # human-readable label
    ast_type: str | None = None  # Python AST node type name
    metadata: dict[str, Any] = Field(default_factory=dict)


class CPGEdge(BaseModel):
    """A directed edge in the Code Property Graph."""

    src: str  # source node id
    dst: str  # destination node id
    edge_type: CPGEdgeType
    metadata: dict[str, Any] = Field(default_factory=dict)


class CodePropertyGraph(BaseModel):
    """The complete Code Property Graph for a project.

    Nodes represent AST elements, and edges carry structural (AST),
    control-flow (CFG), and data-flow (DFG) relationships.
    """

    project_id: str
    language: str = "python"
    node_count: int = 0
    edge_count: int = 0
    nodes: list[CPGNode] = Field(default_factory=list)
    edges: list[CPGEdge] = Field(default_factory=list)

    # Convenience indices (built by the builder)
    file_nodes: list[str] = Field(default_factory=list)
    function_nodes: list[str] = Field(default_factory=list)
    call_nodes: list[str] = Field(default_factory=list)

    def node_by_id(self, node_id: str) -> CPGNode | None:
        """O(1) lookup by id (populated lazily)."""
        if not hasattr(self, "_node_index"):
            self._node_index = {n.id: n for n in self.nodes}
        return self._node_index.get(node_id)

    def edges_from(self, node_id: str, edge_type: CPGEdgeType | None = None) -> list[CPGEdge]:
        """All outgoing edges from a node, optionally filtered by type."""
        return [
            e
            for e in self.edges
            if e.src == node_id and (edge_type is None or e.edge_type == edge_type)
        ]

    def edges_to(self, node_id: str, edge_type: CPGEdgeType | None = None) -> list[CPGEdge]:
        """All incoming edges to a node, optionally filtered by type."""
        return [
            e
            for e in self.edges
            if e.dst == node_id and (edge_type is None or e.edge_type == edge_type)
        ]

    def dfg_reachability(
        self, source_id: str, target_id: str, max_depth: int = 10
    ) -> bool:
        """Check if there is a DFG path from source_id to target_id.

        Simple BFS over DFG edges; bounded by max_depth to avoid cycles.
        """
        from collections import deque

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(source_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if current == target_id:
                return True
            if depth >= max_depth or current in visited:
                continue
            visited.add(current)
            for edge in self.edges_from(current):
                if edge.edge_type.value.startswith("dfg_"):
                    queue.append((edge.dst, depth + 1))
        return False
