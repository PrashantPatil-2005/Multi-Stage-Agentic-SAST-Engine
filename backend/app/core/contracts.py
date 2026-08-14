"""Stage input/output contracts (Pydantic models).

These models are the data contracts between the pipeline stages.
PREPARE consumes a ``RepoSpec`` and produces a ``ProjectSnapshot``
plus a ``CodeModel`` built behind the ``ICodeModelBuilder`` interface.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# PREPARE input
# ---------------------------------------------------------------------------


class RepoSpec(BaseModel):
    """Describes where the target repository comes from."""

    name: str = Field(min_length=1, max_length=200)
    source_type: Literal["directory", "zip", "git"]
    location: str = Field(min_length=1)
    language: Literal["python"] = "python"


# ---------------------------------------------------------------------------
# PREPARE output: ProjectSnapshot
# ---------------------------------------------------------------------------


class SourceLocation(BaseModel):
    line: int
    col: int


class ParseErrorInfo(BaseModel):
    lineno: int
    offset: int
    message: str


class SkipInfo(BaseModel):
    """A file that was deliberately not ingested."""

    path: str
    reason: str


class ImportInfo(BaseModel):
    module: str
    name: str
    alias: str | None
    kind: Literal["import", "from_import", "import_star"]
    file: str
    line: int


class FunctionInfo(BaseModel):
    name: str
    qualified_name: str
    file: str
    line: int
    end_line: int
    args: list[str]
    decorators: list[str]
    is_method: bool
    is_async: bool


class ClassInfo(BaseModel):
    name: str
    file: str
    line: int
    end_line: int
    bases: list[str]
    decorators: list[str]
    methods: list[str]


class CallInfo(BaseModel):
    func: str
    args: list[str]
    num_args: int
    keywords: list[str]
    is_method_call: bool
    file: str
    line: int


class AssignmentInfo(BaseModel):
    targets: list[str]
    value_kind: Literal[
        "call",
        "attribute",
        "name",
        "constant",
        "binary_op",
        "collection",
        "subscript",
        "lambda",
        "ifexp",
        "none",
        "other",
    ]
    value_expr: str
    file: str
    line: int


class SourceFile(BaseModel):
    """Analysis result for one Python file."""

    path: str
    source: str
    sha256: str
    line_count: int
    ast: dict[str, Any] | None
    functions: list[FunctionInfo]
    classes: list[ClassInfo]
    imports: list[ImportInfo]
    calls: list[CallInfo]
    assignments: list[AssignmentInfo]
    error: ParseErrorInfo | None = None


class SnapshotSummary(BaseModel):
    fetched_files: int
    fetched_bytes: int
    python_files: int
    parse_failures: int
    total_lines: int
    function_count: int
    class_count: int
    call_count: int
    import_count: int
    assignment_count: int


class ProjectSnapshot(BaseModel):
    """The complete PREPARE stage output."""

    project_id: str
    repo_name: str
    language: Literal["python"] = "python"
    created_at: datetime
    files: list[SourceFile]
    ignored_paths: list[str]
    skipped_files: list[SkipInfo]
    summary: SnapshotSummary


# ---------------------------------------------------------------------------
# CodeModel (analysis-consumable representation, CPG-extensible)
# ---------------------------------------------------------------------------


class CodeModel(BaseModel):
    """Language-independent code representation consumed by the SCAN stage.

    The Python implementation is produced by ``PythonASTCodeModelBuilder``.
    A future CPG implementation produces the same shape, so SCAN never needs
    to know which builder created it.
    """

    language: Literal["python"] = "python"
    files: list[SourceFile]
    module_map: dict[str, str]
    function_index: list[FunctionInfo]
    built_at: datetime
