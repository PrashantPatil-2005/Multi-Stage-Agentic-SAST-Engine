"""OpenAI-compatible chat-completions provider.

Configuration comes exclusively from environment variables; no credentials
are hardcoded:

* ``LLM_PROVIDER``      - provider id (default ``openai_compatible``)
* ``LLM_BASE_URL``      - e.g. https://api.openai.com/v1 or a self-hosted endpoint
* ``LLM_API_KEY``       - bearer token for the endpoint
* ``LLM_MODEL``         - model id (optional; falls back to a server default)

The scanner remains fully usable without an LLM: providers are only
instantiated when validation is requested, and missing configuration raises
:class:`ConfigurationError` which the API translates into a 503.
"""

import os

import httpx

from app.validate.models import ValidationRequest
from app.validate.prompts import SYSTEM_PROMPT
from app.validate.providers.base import ConfigurationError, LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    provider_name = "openai_compatible"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        self._base_url = (base_url or os.getenv("LLM_BASE_URL", "")).rstrip("/")
        self._api_key = api_key if api_key is not None else os.getenv("LLM_API_KEY", "")
        self._model = model if model is not None else os.getenv("LLM_MODEL", "")
        self._timeout_seconds = timeout_seconds
        if not self._base_url or not self._api_key:
            raise ConfigurationError(
                "LLM is not configured: set LLM_BASE_URL and LLM_API_KEY "
                "(and optionally LLM_PROVIDER / LLM_MODEL) to enable validation"
            )

    @property
    def model(self) -> str | None:
        return self._model or None

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
        with httpx.Client(timeout=self._timeout_seconds) as client:
            response = client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ConfigurationError(
                f"unexpected response shape from {self._base_url}: {exc}"
            ) from exc
