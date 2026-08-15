"""LLM configuration tests (no real API calls, no real tokens)."""

import httpx
import pytest
from httpx import MockTransport

from app.validate.providers import get_provider
from app.validate.providers.base import ConfigurationError
from app.validate.providers.huggingface import DEFAULT_BASE_URL, HuggingFaceLLMProvider

KEY = "hf-test-token-never-real"


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for name in (
        "LLM_PROVIDER",
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_MODEL",
        "LLM_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_llm_config_loads_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "45")
    provider = get_provider()
    assert isinstance(provider, HuggingFaceLLMProvider)
    assert provider.model == "validator-1"


def test_api_key_read_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    provider = get_provider()
    assert provider._api_key == KEY


def test_base_url_read_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://custom.example.com/v1")
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    provider = get_provider()
    assert provider._base_url == "https://custom.example.com/v1"


def test_model_read_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "my-model-id")
    provider = get_provider()
    assert provider.model == "my-model-id"


def test_timeout_read_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "12.5")
    provider = get_provider()
    assert provider._timeout_seconds == 12.5


def test_timeout_defaults_when_unset(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    provider = get_provider()
    assert provider._timeout_seconds == 30.0


def test_missing_api_key_raises_configuration_error(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    with pytest.raises(ConfigurationError, match="not configured"):
        get_provider()


def test_default_base_url_is_hugging_face_router(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    provider = get_provider()
    assert DEFAULT_BASE_URL == "https://router.huggingface.co/v1"
    assert provider._base_url == DEFAULT_BASE_URL


def test_missing_model_raises_configuration_error(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    with pytest.raises(ConfigurationError, match="LLM_MODEL"):
        get_provider()


def test_secrets_never_exposed_in_errors(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.com/v1")
    monkeypatch.setenv("LLM_MODEL", "validator-1")
    provider = get_provider(
        transport=MockTransport(lambda request: (_ for _ in ()).throw(httpx.ConnectError("offline")))
    )
    with pytest.raises(ConfigurationError) as excinfo:
        provider._complete("any prompt")
    assert KEY not in str(excinfo.value)
    assert KEY not in repr(provider)
    assert KEY not in repr(provider._base_url)
    assert KEY not in repr(provider.model)
