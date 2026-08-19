"""DefectDojo HTTP API client.

A real, functional client that communicates with a DefectDojo instance
over HTTP.  No fabricated responses — every method either succeeds with
real API data or returns a structured error.

The client is stateless and re-usable; connection pooling is handled by
httpx (which is already a project dependency).

Error handling:
    * Network errors → DefectDojoClientError with details
    * Authentication errors → DefectDojoAuthError
    * Not-found errors → DefectDojoNotFoundError
    * Validation errors → DefectDojoValidationError
"""

import logging
from typing import Any

import httpx

from app.defectdojo.config import DefectDojoConfig, get_defectdojo_config
from app.defectdojo.models import (
    DefectDojoConnectionTest,
    DefectDojoFindingCreate,
    DefectDojoFindingResponse,
)

logger = logging.getLogger(__name__)


class DefectDojoClientError(Exception):
    """Base error for DefectDojo client operations."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class DefectDojoAuthError(DefectDojoClientError):
    """Authentication failed (401/403)."""
    pass


class DefectDojoNotFoundError(DefectDojoClientError):
    """Resource not found (404)."""
    pass


class DefectDojoValidationError(DefectDojoClientError):
    """Validation error from DefectDojo API (400)."""
    pass


class DefectDojoClient:
    """Real HTTP client for the DefectDojo API.

    Uses httpx for HTTP calls.  Authentication is via API key in the
    Authorization header (DefectDojo's standard approach).
    """

    def __init__(self, config: DefectDojoConfig | None = None) -> None:
        self._config = config or get_defectdojo_config()

    @property
    def is_configured(self) -> bool:
        """True when the client has a URL and API key."""
        return bool(self._config.url and self._config.api_key)

    @property
    def is_enabled(self) -> bool:
        """True when the integration is enabled and configured."""
        return self._config.enabled and self.is_configured

    def _base_url(self) -> str:
        """Return the base URL, stripping trailing slash."""
        return self._config.url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        """Return authentication headers."""
        return {
            "Authorization": f"Token {self._config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _api_url(self, path: str) -> str:
        """Build a full API URL."""
        base = self._base_url()
        return f"{base}/api/v2/{path.lstrip('/')}"

    # ────────────────────────────────────── connection test

    def test_connection(self) -> DefectDojoConnectionTest:
        """Test connectivity to DefectDojo.

        Makes a real API call to verify credentials and reachability.
        """
        if not self.is_configured:
            return DefectDojoConnectionTest(
                success=False,
                message="DefectDojo is not configured (missing URL or API key)",
            )

        url = self._api_url("connection/test")
        try:
            with httpx.Client(timeout=self._config.timeout_seconds) as client:
                response = client.get(url, headers=self._headers())

            if response.status_code == 200:
                data = response.json() if response.text else {}
                version = data.get("version") or data.get("scm_branch")
                return DefectDojoConnectionTest(
                    success=True,
                    message="Connected to DefectDojo successfully",
                    url=self._config.url,
                    version=version,
                )
            elif response.status_code in (401, 403):
                return DefectDojoConnectionTest(
                    success=False,
                    message=f"Authentication failed (HTTP {response.status_code}). "
                    "Check your API key.",
                    url=self._config.url,
                )
            else:
                return DefectDojoConnectionTest(
                    success=False,
                    message=f"DefectDojo returned HTTP {response.status_code}: "
                    f"{response.text[:200]}",
                    url=self._config.url,
                )

        except httpx.ConnectError as exc:
            return DefectDojoConnectionTest(
                success=False,
                message=f"Cannot connect to DefectDojo at {self._config.url}: {exc}",
                url=self._config.url,
            )
        except httpx.TimeoutException:
            return DefectDojoConnectionTest(
                success=False,
                message=f"Connection to DefectDojo timed out after "
                f"{self._config.timeout_seconds}s",
                url=self._config.url,
            )
        except Exception as exc:
            return DefectDojoConnectionTest(
                success=False,
                message=f"Unexpected error connecting to DefectDojo: {exc}",
                url=self._config.url,
            )

    # ────────────────────────────────────── finding creation

    def create_finding(self, finding: DefectDojoFindingCreate) -> DefectDojoFindingResponse:
        """Create a finding in DefectDojo.

        Returns the created finding response or raises on error.
        """
        if not self.is_enabled:
            raise DefectDojoClientError(
                "DefectDojo integration is not enabled. "
                "Set SAST_DEFECTDOJO_ENABLED=true and configure URL/API key."
            )

        url = self._api_url("findings/")
        payload = finding.model_dump(exclude_none=True)

        try:
            with httpx.Client(timeout=self._config.timeout_seconds) as client:
                response = client.post(url, json=payload, headers=self._headers())

            if response.status_code in (200, 201):
                data = response.json()
                return DefectDojoFindingResponse(
                    id=data["id"],
                    url=data.get("url", ""),
                    title=data.get("title", finding.title),
                    severity=data.get("severity", finding.severity),
                    numerical_severity=data.get("numerical_severity", finding.numerical_severity),
                    active=data.get("active", True),
                    verified=data.get("verified", False),
                    created=data.get("created", ""),
                    updated=data.get("updated", ""),
                )
            elif response.status_code in (401, 403):
                raise DefectDojoAuthError(
                    f"Authentication failed (HTTP {response.status_code})",
                    status_code=response.status_code,
                )
            elif response.status_code == 400:
                raise DefectDojoValidationError(
                    f"Validation error: {response.text[:500]}",
                    status_code=400,
                    response_body=response.text,
                )
            elif response.status_code == 404:
                raise DefectDojoNotFoundError(
                    "API endpoint not found. Check your DefectDojo URL.",
                    status_code=404,
                )
            else:
                raise DefectDojoClientError(
                    f"DefectDojo returned HTTP {response.status_code}: "
                    f"{response.text[:300]}",
                    status_code=response.status_code,
                    response_body=response.text,
                )

        except httpx.ConnectError as exc:
            raise DefectDojoClientError(
                f"Cannot connect to DefectDojo: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise DefectDojoClientError(
                f"DefectDojo request timed out after {self._config.timeout_seconds}s"
            ) from exc

    # ────────────────────────────────────── finding update

    def update_finding(
        self, defectdojo_finding_id: int, updates: dict[str, Any]
    ) -> DefectDojoFindingResponse:
        """Update an existing finding in DefectDojo."""
        if not self.is_enabled:
            raise DefectDojoClientError("DefectDojo integration is not enabled.")

        url = self._api_url(f"findings/{defectdojo_finding_id}/")

        try:
            with httpx.Client(timeout=self._config.timeout_seconds) as client:
                response = client.patch(url, json=updates, headers=self._headers())

            if response.status_code == 200:
                data = response.json()
                return DefectDojoFindingResponse(
                    id=data["id"],
                    url=data.get("url", ""),
                    title=data.get("title", ""),
                    severity=data.get("severity", ""),
                    numerical_severity=data.get("numerical_severity", 0),
                    active=data.get("active", True),
                    verified=data.get("verified", False),
                    created=data.get("created", ""),
                    updated=data.get("updated", ""),
                )
            else:
                raise DefectDojoClientError(
                    f"DefectDojo update failed (HTTP {response.status_code}): "
                    f"{response.text[:300]}",
                    status_code=response.status_code,
                )

        except httpx.ConnectError as exc:
            raise DefectDojoClientError(f"Cannot connect to DefectDojo: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise DefectDojoClientError(
                f"DefectDojo request timed out after {self._config.timeout_seconds}s"
            ) from exc
