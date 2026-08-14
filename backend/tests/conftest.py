"""Shared fixtures for the PREPARE stage test suite."""

from pathlib import Path

import pytest

from app.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_repo() -> Path:
    return FIXTURES / "vulnerable_python_app"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        workspace_dir=tmp_path / "workspace",
        database_url="sqlite:///:memory:",
        log_level="WARNING",
    )


@pytest.fixture
def fetcher(settings):
    from app.prepare.fetcher import RepoFetcher

    return RepoFetcher(settings)


@pytest.fixture
def service(settings):
    from app.prepare.service import PrepareService

    return PrepareService(settings)


@pytest.fixture
def client(settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client
