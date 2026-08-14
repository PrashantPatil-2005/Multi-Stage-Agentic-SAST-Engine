"""ORM models (PREPARE stage: only projects)."""

from datetime import datetime

from sqlalchemy import DateTime, String
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
