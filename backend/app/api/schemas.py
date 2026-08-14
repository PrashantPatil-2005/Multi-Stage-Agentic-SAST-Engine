"""API schemas for the PREPARE stage endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.contracts import ParseErrorInfo, SnapshotSummary


class FileMeta(BaseModel):
    """Lightweight per-file metadata (source code is intentionally omitted)."""

    path: str
    sha256: str
    line_count: int
    functions: int
    classes: int
    imports: int
    calls: int
    assignments: int
    error: ParseErrorInfo | None = None


class ProjectOut(BaseModel):
    id: str
    name: str
    source_type: str
    location: str
    language: str
    status: str
    created_at: datetime
    summary: SnapshotSummary


class ProjectDetail(ProjectOut):
    files: list[FileMeta] = Field(default_factory=list)
