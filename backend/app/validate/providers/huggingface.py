"""Hugging Face Inference (OpenAI-compatible router) provider.

Production VALIDATE backend. Talks to the Hugging Face router
(``https://router.huggingface.co/v1``) with a ``Bearer`` token.

Configuration comes exclusively from environment variables (reused from the
existing LLM configuration; no duplicates introduced):

* ``LLM_PROVIDER``         - provider id (default ``huggingface``)
* ``LLM_BASE_URL``         - default ``https://router.huggingface.co/v1``
* ``LLM_API_KEY``          - Hugging Face token (never hardcoded)
* ``LLM_MODEL``            - model id (required by the router)
* ``LLM_TIMEOUT_SECONDS``  - request timeout (default 30)

The token is never logged, echoed in responses, or included in exception
messages. Missing configuration raises :class:`ConfigurationError`, which
the API translates into a 503 - the application never crashes and never
fabricates a verdict.
"""

import os

from app.validate.providers.base import ConfigurationError
from app.validate.providers.openai_compatible import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://router.huggingface.co/v1"


class HuggingFaceLLMProvider(OpenAICompatibleProvider):
    provider_name = "huggingface"

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        transport=None,
    ) -> None:
        base_url = base_url or os.getenv("LLM_BASE_URL", DEFAULT_BASE_URL)
        super().__init__(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        if not self._model:
            raise ConfigurationError(
                "LLM is not configured: set LLM_MODEL to the Hugging Face model id "
                "(e.g. a model hosted on or routed through the Inference API)"
            )
