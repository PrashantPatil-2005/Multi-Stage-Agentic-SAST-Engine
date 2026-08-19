"""DefectDojo configuration from environment variables.

All settings use the SAST_ prefix (pydantic-settings convention) and
fall back to sensible defaults.  The integration is disabled by default
and must be explicitly enabled.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DefectDojoConfig(BaseSettings):
    """DefectDojo connection and behaviour settings."""

    model_config = SettingsConfigDict(
        env_prefix="SAST_DEFECTDOJO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    url: str = Field(
        default="",
        description="Base URL of the DefectDojo instance (e.g. https://defectdojo.example.com)",
    )
    api_key: str = Field(
        default="",
        description="API token for DefectDojo authentication",
    )
    enabled: bool = Field(
        default=False,
        description="Set to true to enable DefectDojo integration",
    )
    product_id: int | None = Field(
        default=None,
        description="Default DefectDojo product ID for new findings",
    )
    engagement_id: int | None = Field(
        default=None,
        description="Default DefectDojo engagement ID for new findings",
    )
    test_type_name: str = Field(
        default="SAST Engine",
        description="Test type name to use when creating findings",
    )
    timeout_seconds: int = Field(
        default=30,
        description="HTTP request timeout for DefectDojo API calls",
    )


_config: DefectDojoConfig | None = None


def get_defectdojo_config() -> DefectDojoConfig:
    """Return the singleton DefectDojo configuration."""
    global _config
    if _config is None:
        _config = DefectDojoConfig()
    return _config


def reset_defectdojo_config() -> None:
    """Reset the singleton (for testing)."""
    global _config
    _config = None
