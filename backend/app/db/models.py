"""ORM models (PREPARE stage projects + pipeline state persistence).

Each pipeline record is stored as a primary key plus a JSON ``payload``
holding the complete Pydantic model dump. Rehydration validates the payload
back into the original Pydantic model, so no field is ever dropped and the
Pydantic models remain the single source of truth for the API contracts.

Pipeline rows deliberately use no foreign keys: summary endpoints must
tolerate orphan records (records whose finding no longer exists), and the
tests cover that tolerance explicitly. ``clear()`` deletes each table
outright, so referential cleanup is handled in code, not by the database.
"""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(20))
    location: Mapped[str] = mapped_column(String(500))
    language: Mapped[str] = mapped_column(String(20), default="python")
    status: Mapped[str] = mapped_column(String(20), default="prepared")
    snapshot_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FindingRow(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class DeduplicationGroupRow(Base):
    __tablename__ = "deduplication_groups"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class RiskAssessmentRow(Base):
    __tablename__ = "risk_assessments"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class SlaRecordRow(Base):
    __tablename__ = "sla_records"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class SlaEventRow(Base):
    __tablename__ = "sla_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)


class ValidationResultRow(Base):
    __tablename__ = "validation_results"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ProofResultRow(Base):
    __tablename__ = "proof_results"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ApprovalRequestRow(Base):
    __tablename__ = "approval_requests"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)


class ApprovalEventRow(Base):
    __tablename__ = "approval_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    approval_id: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSON)


class BenchmarkReportRow(Base):
    __tablename__ = "benchmark_reports"

    benchmark_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ScanRunRow(Base):
    __tablename__ = "scan_runs"

    scan_run_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON)


class ScanStageRunRow(Base):
    __tablename__ = "scan_stage_runs"

    scan_run_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    stage_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ScanStageExecutionRow(Base):
    """Append-only history of one stage execution within a scan run."""

    __tablename__ = "scan_stage_executions"

    execution_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_run_id: Mapped[str] = mapped_column(String(32))
    stage_name: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON)


class ScanFindingRow(Base):
    """Explicit scan -> finding lineage (a finding may appear in many runs)."""

    __tablename__ = "scan_findings"

    scan_run_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)


class RemediationRow(Base):
    """Post-approval remediation workflow record (one per finding)."""

    __tablename__ = "remediation_records"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)


class NotificationReadRow(Base):
    """Per-user notification read state (derived notifications with read_at)."""

    __tablename__ = "notification_reads"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32))
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserRow(Base):
    """Persistent user record for authentication."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRow(Base):
    """Server-side session record."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)