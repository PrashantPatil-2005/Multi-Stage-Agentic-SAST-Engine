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


class ScanResponse(BaseModel):
    """Result of running the existing SCAN stage on a prepared project.

    Only summary data is returned; the full findings are available through
    the read-only /api/findings endpoints (registered in the finding store).
    """

    report_id: str
    project_id: str
    created_at: datetime
    scanned_file_count: int
    total_findings: int
    by_type: dict[str, int] = Field(default_factory=dict)
    finding_ids: list[str] = Field(default_factory=list)
