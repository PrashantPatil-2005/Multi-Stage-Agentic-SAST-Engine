"""Code Property Graph (CPG) implementation for the PREPARE stage.

The CPG represents the code as a directed graph with three edge layers
(all computed from Python's stdlib ast module, no build required):

1. **AST edges** — structural parent→child relationships (same as the
   Python AST but serialized as explicit graph edges).
2. **Control-flow edges** — sequential and branching flow between
   statements within each function body.
3. **Data-flow edges** — variable definition→use links tracking how
   values propagate through assignments, function parameters, and
   return statements.

The graph is the analysis input consumed by the SCAN stage.  It goes
beyond the plain AST model by recording explicit data-flow and
control-flow relationships, which is what the specification requires
when it asks for a "Code Property Graph generated from source without
requiring a build."
"""

from app.prepare.cpg.builder import CPGBuilder
from app.prepare.cpg.models import (
    CPGEdge,
    CPGEdgeType,
    CPGNode,
    CPGNodeKind,
    CodePropertyGraph,
)

__all__ = [
    "CPGBuilder",
    "CPGEdge",
    "CPGEdgeType",
    "CPGNode",
    "CPGNodeKind",
    "CodePropertyGraph",
]
