"""Shared fixtures for the PREPARE stage test suite."""

from pathlib import Path

import pytest

from app.config import Settings
from app.auth.seed import DEMO_PASSWORD

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
    """TestClient pre-authenticated as the demo manager (full permissions).

    Existing tests rely on this fixture and do not supply authentication
    themselves, so the fixture logs in as 'manager' to avoid 401/403 on
    every endpoint call.
    """
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(settings)
    with TestClient(app) as test_client:
        # Log in as manager (has all permissions including approve/delete)
        resp = test_client.post(
            "/api/auth/login",
            json={"username": "manager", "password": DEMO_PASSWORD},
        )
        assert resp.status_code == 200, f"conftest login failed: {resp.text}"
        yield test_client
