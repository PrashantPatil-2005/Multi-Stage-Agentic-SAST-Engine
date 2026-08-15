"""Provider factory for VALIDATE.

``get_provider`` resolves the configured LLM backend from environment
variables. Raises :class:`ConfigurationError` with a clear message when no
usable configuration exists - the scanner itself never depends on an LLM.
"""

import os

from app.validate.providers.base import ConfigurationError, LLMProvider
from app.validate.providers.huggingface import HuggingFaceLLMProvider
from app.validate.providers.openai_compatible import OpenAICompatibleProvider

_PROVIDERS = {
    "huggingface": HuggingFaceLLMProvider,
    "openai_compatible": OpenAICompatibleProvider,
}


def get_provider(name: str | None = None, **kwargs) -> LLMProvider:
    """Build the configured provider.

    ``name`` defaults to ``LLM_PROVIDER`` (``huggingface``); extra kwargs
    (base_url, api_key, model) override environment variables, which keeps
    tests hermetic.
    """
    provider_name = name or os.getenv("LLM_PROVIDER", "huggingface")
    factory = _PROVIDERS.get(provider_name)
    if factory is None:
        raise ConfigurationError(
            f"unknown LLM provider {provider_name!r}; "
            f"supported: {sorted(_PROVIDERS)}"
        )
    try:
        return factory(**kwargs)
    except ConfigurationError as exc:
        raise ConfigurationError(f"provider {provider_name!r}: {exc}") from exc
