"""Application configuration via environment variables (.env supported).

All settings are overridable with the SAST_ prefix, e.g. SAST_WORKSPACE_DIR.
No secrets are hardcoded anywhere in the codebase.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SAST_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Multi-Stage Agentic SAST Engine"
    app_version: str = "0.1.0"

    workspace_dir: Path = Path("workspace")

    # SQLite for local development; PostgreSQL via DATABASE_URL later.
    database_url: str = "sqlite:///./sast.db"

    # Ingestion limits
    max_file_size_bytes: int = 1 * 1024 * 1024
    max_total_size_bytes: int = 50 * 1024 * 1024
    max_files: int = 5000
    git_clone_timeout_seconds: int = 60

    # Background SLA evaluation: how often the evaluator inspects active
    # SLA records (seconds). Conservative for development; must be >= 1.
    sla_check_interval_seconds: int = Field(default=60, gt=0)

    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
