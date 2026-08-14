"""Parser tests: AST extraction, hashing, error handling."""

import hashlib

from app.core.contracts import SourceFile
from app.prepare.parser import PythonASTParser

parser = PythonASTParser()


def test_valid_file_parse():
    source = (
        "import os\n"
        "\n"
        "def greet(name: str) -> str:\n"
        "    return f'hello {name}'\n"
    )
    file = parser.parse("greet.py", source)
    assert isinstance(file, SourceFile)
    assert file.error is None
    assert file.ast is not None
    assert file.ast["type"] == "Module"
    assert file.line_count == 4
    assert [f.name for f in file.functions] == ["greet"]
    assert file.functions[0].qualified_name == "greet"
    assert file.functions[0].args == ["name"]
    assert file.functions[0].line == 3
    assert file.functions[0].end_line == 4
    assert [i.module for i in file.imports] == ["os"]


def test_syntax_error_file():
    file = parser.parse("broken.py", "def broken(:\n    pass\n")
    assert file.error is not None
    assert file.error.lineno == 1
    assert file.ast is None
    assert file.functions == []


def test_source_hashing():
    source = "x = 1\n"
    file = parser.parse("h.py", source)
    expected = hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert file.sha256 == expected
    assert len(file.sha256) == 64


def test_calls_and_assignments_collected():
    source = (
        "import subprocess\n"
        "\n"
        "def run(cmd):\n"
        "    result = subprocess.run(cmd, shell=True)\n"
        "    return result\n"
    )
    file = parser.parse("c.py", source)
    assert any(c.func == "subprocess.run" for c in file.calls)
    call = next(c for c in file.calls if c.func == "subprocess.run")
    assert call.num_args == 2
    assert "shell" in call.keywords
    assert call.line == 4
    assert file.assignments[0].targets == ["result"]
    assert file.assignments[0].value_kind == "call"


def test_async_function_detected():
    source = "async def fetch(url):\n    return await client.get(url)\n"
    file = parser.parse("a.py", source)
    assert file.functions[0].is_async is True


def test_ast_dump_is_json_serializable():
    import json

    source = "def f(a, b=1):\n    return a + b\n"
    file = parser.parse("j.py", source)
    json.dumps(file.ast)  # must not raise
