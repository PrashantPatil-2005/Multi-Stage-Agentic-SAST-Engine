"""DefectDojo integration for remediation ticket workflows.

This module provides a real API client and service layer for creating
and managing findings in DefectDojo.  It does NOT fabricate responses
or simulate the DefectDojo API — when the server is unreachable or
credentials are missing, the integration returns clear error states.

Configuration (environment variables):
    SAST_DEFECTDOJO_URL      — Base URL of the DefectDojo instance
    SAST_DEFECTDOJO_API_KEY  — API token for authentication
    SAST_DEFECTDOJO_ENABLED  — "true" to enable integration (default: false)
"""
