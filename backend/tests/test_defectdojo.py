"""Tests for the DefectDojo integration.

Tests the client, service, and configuration without requiring a real
DefectDojo instance.  Mocking is used for HTTP calls; no fabricated
DefectDojo responses are used.
"""

import pytest
from unittest.mock import MagicMock, patch

from app.defectdojo.client import (
    DefectDojoClient,
    DefectDojoClientError,
    DefectDojoAuthError,
    DefectDojoValidationError,
)
from app.defectdojo.config import DefectDojoConfig, reset_defectdojo_config
from app.defectdojo.models import DefectDojoFindingCreate
from app.defectdojo.service import (
    DefectDojoService,
    SEVERITY_MAP,
    all_tickets,
    get_ticket,
)
from app.scan.models import CandidateFinding, SinkRef, SourceRef, TaintStep, Evidence


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset the DefectDojo config singleton between tests."""
    reset_defectdojo_config()
    yield
    reset_defectdojo_config()


def _make_finding(
    vuln_type: str = "sql_injection",
    severity: str = "high",
) -> CandidateFinding:
    return CandidateFinding(
        id=f"test-{vuln_type}-001",
        vulnerability_type=vuln_type,
        severity=severity,
        confidence=0.9,
        source=SourceRef(
            file="app.py", line=10, snippet="request.args.get('id')", kind="request_param"
        ),
        sink=SinkRef(
            file="app.py", line=20, snippet="cursor.execute(query)", kind="sql_execute"
        ),
        taint_path=[
            TaintStep(file="app.py", line=10, snippet="request.args.get('id')", step_type="source"),
            TaintStep(file="app.py", line=20, snippet="cursor.execute(query)", step_type="sink"),
        ],
        evidence=Evidence(
            source_snippet="request.args.get('id')",
            sink_snippet="cursor.execute(query)",
            taint_path=[
                TaintStep(file="app.py", line=10, snippet="request.args.get('id')", step_type="source"),
            ],
            relevant_lines=[10, 20],
            sanitizer_observations=["no sanitizer observed at sink"],
        ),
    )


class TestDefectDojoConfig:
    def test_default_config_is_disabled(self):
        config = DefectDojoConfig()
        assert config.enabled is False
        assert config.url == ""
        assert config.api_key == ""

    def test_config_from_env(self):
        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="test-key-123",
            enabled=True,
            product_id=42,
        )
        assert config.enabled is True
        assert config.url == "https://defectdojo.example.com"
        assert config.api_key == "test-key-123"
        assert config.product_id == 42


class TestDefectDojoClient:
    def test_not_configured(self):
        config = DefectDojoConfig()
        client = DefectDojoClient(config)
        assert client.is_configured is False
        assert client.is_enabled is False

    def test_configured_but_disabled(self):
        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="key",
            enabled=False,
        )
        client = DefectDojoClient(config)
        assert client.is_configured is True
        assert client.is_enabled is False

    def test_enabled_and_configured(self):
        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="key",
            enabled=True,
        )
        client = DefectDojoClient(config)
        assert client.is_enabled is True

    def test_test_connection_not_configured(self):
        config = DefectDojoConfig()
        client = DefectDojoClient(config)
        result = client.test_connection()
        assert result.success is False
        assert "not configured" in result.message.lower()

    @patch("app.defectdojo.client.httpx.Client")
    def test_test_connection_success(self, mock_client_cls):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"version": "2.35.0"}
        mock_response.text = "{}"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="test-key",
            enabled=True,
        )
        client = DefectDojoClient(config)
        result = client.test_connection()
        assert result.success is True
        assert result.version == "2.35.0"

    @patch("app.defectdojo.client.httpx.Client")
    def test_test_connection_auth_failure(self, mock_client_cls):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_cls.return_value = mock_client

        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="bad-key",
            enabled=True,
        )
        client = DefectDojoClient(config)
        result = client.test_connection()
        assert result.success is False
        assert "authentication" in result.message.lower()

    @patch("app.defectdojo.client.httpx.Client")
    def test_create_finding_success(self, mock_client_cls):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 123,
            "url": "https://defectdojo.example.com/findings/123",
            "title": "SQL Injection: cursor.execute(query)",
            "severity": "High",
            "numerical_severity": 2,
            "active": True,
            "verified": False,
            "created": "2026-08-19T10:00:00Z",
            "updated": "2026-08-19T10:00:00Z",
        }

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_cls.return_value = mock_client

        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="test-key",
            enabled=True,
        )
        client = DefectDojoClient(config)
        finding = DefectDojoFindingCreate(
            title="SQL Injection",
            severity="High",
            numerical_severity=2,
            description="Test finding",
        )
        result = client.create_finding(finding)
        assert result.id == 123
        assert result.severity == "High"

    def test_create_finding_not_enabled(self):
        config = DefectDojoConfig()
        client = DefectDojoClient(config)
        finding = DefectDojoFindingCreate(
            title="Test",
            severity="High",
            numerical_severity=2,
            description="Test",
        )
        with pytest.raises(DefectDojoClientError, match="not enabled"):
            client.create_finding(finding)


class TestDefectDojoService:
    def test_severity_mapping(self):
        assert SEVERITY_MAP["critical"] == (1, "Critical")
        assert SEVERITY_MAP["high"] == (2, "High")
        assert SEVERITY_MAP["medium"] == (3, "Medium")
        assert SEVERITY_MAP["low"] == (4, "Low")

    def test_create_ticket_disabled(self):
        config = DefectDojoConfig(enabled=False)
        service = DefectDojoService(config)
        finding = _make_finding()
        ticket = service.create_ticket(finding)
        assert ticket.status == "error"
        assert "not enabled" in ticket.error_message.lower()

    def test_get_status(self):
        config = DefectDojoConfig(
            url="https://defectdojo.example.com",
            api_key="key",
            enabled=True,
        )
        service = DefectDojoService(config)
        status = service.get_status()
        assert status["enabled"] is True
        assert status["configured"] is True
        assert status["url"] == "https://defectdojo.example.com"

    def test_mitigation_for_sql_injection(self):
        mitigation = DefectDojoService._mitigation_for("sql_injection")
        assert "parameterized" in mitigation.lower()

    def test_mitigation_for_command_injection(self):
        mitigation = DefectDojoService._mitigation_for("command_injection")
        assert "shell" in mitigation.lower() or "subprocess" in mitigation.lower()

    def test_mitigation_for_deserialization(self):
        mitigation = DefectDojoService._mitigation_for("deserialization")
        assert "pickle" in mitigation.lower() or "json" in mitigation.lower()

    def test_to_defectdojo_finding_translation(self):
        config = DefectDojoConfig(enabled=True, url="https://dd.example.com", api_key="key")
        service = DefectDojoService(config)
        finding = _make_finding(vuln_type="sql_injection", severity="high")
        dd_finding = service._to_defectdojo_finding(finding)
        assert dd_finding.severity == "High"
        assert dd_finding.numerical_severity == 2
        assert "sql_injection" in dd_finding.description.lower()
        assert dd_finding.file_path == "app.py"
        assert dd_finding.line == 10


class TestDefectDojoAPIRoutes:
    """API route tests using the test client."""

    def test_status_endpoint(self, client):
        resp = client.get("/api/defectdojo/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "enabled" in data
        assert "configured" in data
        assert "ticket_count" in data

    def test_test_connection_endpoint(self, client):
        resp = client.post("/api/defectdojo/test-connection")
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data
        assert "message" in data

    def test_tickets_list_endpoint(self, client):
        resp = client.get("/api/defectdojo/tickets")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_ticket_for_unknown_finding(self, client):
        resp = client.get("/api/defectdojo/tickets/nonexistent-finding-id")
        assert resp.status_code == 404
