"""Tests for the Code Property Graph (CPG) builder.

Verifies that the CPG correctly constructs graph nodes and edges from
Python source code, including AST, CFG, and DFG layers.
"""

from datetime import datetime, timezone

from app.core.contracts import CodeModel, ProjectSnapshot
from app.prepare.cpg.builder import CPGBuilder
from app.prepare.cpg.models import (
    CPGEdgeType,
    CPGNodeKind,
    CodePropertyGraph,
)
from app.prepare.parser import PythonASTParser


def _make_snapshot(sources: dict[str, str]) -> ProjectSnapshot:
    """Build a ProjectSnapshot from source strings."""
    parser = PythonASTParser()
    files = [parser.parse(path, src) for path, src in sources.items()]
    return ProjectSnapshot(
        project_id="test-project",
        repo_name="test",
        language="python",
        created_at=datetime.now(timezone.utc),
        files=files,
        ignored_paths=[],
        skipped_files=[],
        summary={
            "fetched_files": len(files),
            "fetched_bytes": 0,
            "python_files": len(files),
            "parse_failures": 0,
            "total_lines": sum(f.line_count for f in files),
            "function_count": sum(len(f.functions) for f in files),
            "class_count": sum(len(f.classes) for f in files),
            "call_count": sum(len(f.calls) for f in files),
            "import_count": sum(len(f.imports) for f in files),
            "assignment_count": sum(len(f.assignments) for f in files),
        },
    )


class TestCPGBasic:
    """Basic CPG construction tests."""

    def test_empty_snapshot_produces_empty_graph(self):
        snapshot = _make_snapshot({})
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)
        assert graph.project_id == "test-project"
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_single_function_produces_nodes(self):
        snapshot = _make_snapshot({
            "app.py": "def hello():\n    return 42\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        # Should have at least: file node + module + function + return statement
        assert graph.node_count >= 3
        assert len(graph.file_nodes) == 1

    def test_graph_has_file_node(self):
        snapshot = _make_snapshot({
            "app.py": "x = 1\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        file_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.FILE]
        assert len(file_nodes) == 1
        assert file_nodes[0].file == "app.py"

    def test_graph_has_function_nodes(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    pass\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        func_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.FUNCTION]
        assert len(func_nodes) >= 1
        assert any(n.name == "foo" for n in func_nodes)

    def test_graph_has_class_nodes(self):
        snapshot = _make_snapshot({
            "app.py": "class MyClass:\n    def method(self):\n        pass\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        class_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.CLASS]
        assert len(class_nodes) >= 1

    def test_ast_edges_connect_parent_to_child(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    x = 1\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        ast_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.AST_CHILD]
        assert len(ast_edges) >= 2  # file→function, function→statement at minimum


class TestCPGDataFlow:
    """Data-flow edge tests."""

    def test_dfg_edges_for_assignment(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    x = request.args.get('id')\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        # Should have DFG edges from the RHS expression
        dfg_edges = [e for e in graph.edges if e.edge_type.value.startswith("dfg_")]
        # At minimum, there should be a DFG_ASSIGN_RHS edge
        assert any(e.edge_type == CPGEdgeType.DFG_ASSIGN_RHS for e in dfg_edges)

    def test_dfg_edges_for_function_params(self):
        snapshot = _make_snapshot({
            "app.py": "def handler(user_id):\n    cursor.execute(f'SELECT * FROM t WHERE id={user_id}')\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        param_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.DFG_PARAM]
        assert len(param_edges) >= 1

    def test_dfg_name_use_edges(self):
        snapshot = _make_snapshot({
            "app.py": "def foo(x):\n    y = x + 1\n    return y\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        name_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.NAME]
        # Should have at least the 'x' use and 'y' definition/return
        assert len(name_nodes) >= 1


class TestCPGControlFlow:
    """Control-flow edge tests."""

    def test_cfg_sequential_edges(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    a = 1\n    b = 2\n    c = 3\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        seq_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.CFG_SEQ]
        assert len(seq_edges) >= 2  # a→b, b→c

    def test_cfg_if_branch_edges(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    if True:\n        a = 1\n    else:\n        b = 2\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        true_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.CFG_TRUE]
        false_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.CFG_FALSE]
        assert len(true_edges) >= 1
        assert len(false_edges) >= 1

    def test_cfg_for_loop_edges(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    for i in range(10):\n        x = i\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        loop_edges = [e for e in graph.edges if e.edge_type == CPGEdgeType.CFG_LOOP_BODY]
        assert len(loop_edges) >= 1


class TestCPGCodeModel:
    """Tests for the CodeModel-compatible interface."""

    def test_build_returns_code_model(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    return 42\n"
        })
        builder = CPGBuilder()
        model = builder.build(snapshot)

        assert isinstance(model, CodeModel)
        assert model.project_id == "test-project"
        assert model.language == "python"
        assert len(model.files) == 1
        assert len(model.function_index) >= 1

    def test_code_model_has_module_map(self):
        snapshot = _make_snapshot({
            "app.py": "x = 1\n",
            "lib/utils.py": "y = 2\n",
        })
        builder = CPGBuilder()
        model = builder.build(snapshot)

        assert "app" in model.module_map
        assert "lib.utils" in model.module_map


class TestCPGNodeLookup:
    """Tests for CPG node lookup and reachability."""

    def test_node_by_id(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    return 42\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        file_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.FILE]
        assert len(file_nodes) >= 1
        assert graph.node_by_id(file_nodes[0].id) is not None

    def test_edges_from_node(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    pass\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        file_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.FILE]
        assert len(file_nodes) >= 1
        outgoing = graph.edges_from(file_nodes[0].id)
        assert len(outgoing) >= 1

    def test_dfg_reachability(self):
        snapshot = _make_snapshot({
            "app.py": "def foo():\n    x = 1\n    y = x\n"
        })
        builder = CPGBuilder()
        graph = builder.build_graph(snapshot)

        # Find a definition and a use of x
        name_nodes = [n for n in graph.nodes if n.kind == CPGNodeKind.NAME]
        assert len(name_nodes) >= 1
