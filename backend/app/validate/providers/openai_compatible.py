"""OpenAI-compatible chat-completions provider.

Configuration comes exclusively from environment variables; no credentials
are hardcoded:

* ``LLM_PROVIDER``      - provider id (default ``huggingface``)
* ``LLM_BASE_URL``      - e.g. https://api.openai.com/v1 or a self-hosted endpoint
* ``LLM_API_KEY``       - bearer token for the endpoint
* ``LLM_MODEL``         - model id (required by the Hugging Face router)
* ``LLM_TIMEOUT_SECONDS`` - request timeout (default 30)

The scanner remains fully usable without an LLM: providers are only
instantiated when validation is requested, and missing configuration raises
:class:`ConfigurationError` which the API translates into a 503.

All provider errors (auth, rate limit, 5xx, timeout, network, malformed
bodies) are translated into safe :class:`ConfigurationError` messages that
never contain the API key or other secrets.
"""

import json
import logging
import os

import httpx

from app.validate.models import ValidationRequest
from app.validate.prompts import SYSTEM_PROMPT
from app.validate.providers.base import ConfigurationError, LLMProvider

logger = logging.getLogger(__name__)

_UNAVAILABLE = "LLM validation is currently unavailable"


class OpenAICompatibleProvider(LLMProvider):
    provider_name = "openai_compatible"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = (base_url or os.getenv("LLM_BASE_URL", "")).rstrip("/")
        self._api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        self._model = model if model is not None else os.getenv("LLM_MODEL", "")
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else _env_float("LLM_TIMEOUT_SECONDS", 30.0)
        )
        self._transport = transport
        if not self._base_url or not self._api_key:
            raise ConfigurationError(
                "LLM is not configured: set LLM_BASE_URL and LLM_API_KEY "
                "(and optionally LLM_PROVIDER / LLM_MODEL) to enable validation"
            )

    @property
    def model(self) -> str | None:
        return self._model or None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(provider_name={self.provider_name!r}, "
            f"base_url={self._base_url!r}, model={self.model!r}, api_key=<redacted>)"
        )

    def _complete(self, prompt: str) -> str:
        payload = {
            "model": self._model or "default",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
                response = client.post(
                    f"{self._base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
        except httpx.TimeoutException as exc:
            raise ConfigurationError(
                f"{_UNAVAILABLE}: the model request timed out"
            ) from exc
        except httpx.RequestError as exc:
            logger.warning("LLM network error (%s)", type(exc).__name__)
            raise ConfigurationError(
                f"{_UNAVAILABLE}: network error while contacting the model endpoint"
            ) from exc
        if response.status_code in (401, 403):
            logger.warning("LLM auth rejected (status=%s)", response.status_code)
            raise ConfigurationError(
                f"{_UNAVAILABLE}: the API key was rejected by the provider"
            )
        if response.status_code == 429:
            logger.warning("LLM rate limited (status=429)")
            raise ConfigurationError(f"{_UNAVAILABLE}: rate limited by the provider")
        if response.status_code >= 500:
            logger.warning("LLM provider error (status=%s)", response.status_code)
            raise ConfigurationError(
                f"{_UNAVAILABLE}: provider error (status {response.status_code})"
            )
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning("LLM provider error (status=%s)", exc.response.status_code)
            raise ConfigurationError(
                f"{_UNAVAILABLE}: provider error (status {exc.response.status_code})"
            ) from exc
        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning("LLM malformed response body")
            raise ConfigurationError(f"{_UNAVAILABLE}: malformed provider response") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ConfigurationError(
                f"{_UNAVAILABLE}: unexpected response shape from the provider"
            ) from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("ignoring invalid %s value %r", name, raw)
        return default
