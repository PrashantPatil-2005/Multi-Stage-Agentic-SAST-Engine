"""Explicit benchmark ground truth for controlled fixtures.

Ground truth is authoritative for benchmark metrics and is written by
inspection of the fixture sources — it is NEVER inferred from what either
scanner reports.

Safe cases are represented deliberately: if a tool reports a safe case as
vulnerable, that finding counts as a false positive.
"""

from pydantic import BaseModel


class GroundTruthCase(BaseModel):
    case_id: str
    file: str
    function: str
    vulnerability_type: str
    expected_vulnerable: bool
    source_description: str
    sink_description: str
    source_line: int
    sink_line: int


def _cases(*entries: dict) -> list[GroundTruthCase]:
    return [GroundTruthCase(**entry) for entry in entries]


# lines refer to backend/tests/fixtures/vulnerable_python_app/
FIXTURE_GROUND_TRUTH: dict[str, list[GroundTruthCase]] = {
    "vulnerable_python_app": _cases(
        # ---------------------------------------------------- app.py: SQLi
        {
            "case_id": "sql-app-get-user",
            "file": "app.py",
            "function": "get_user",
            "vulnerability_type": "sql_injection",
            "expected_vulnerable": True,
            "source_description": "user_id parameter interpolated into SQL",
            "sink_description": "conn.execute(query) with f-string query",
            "source_line": 12,
            "sink_line": 15,
        },
        {
            "case_id": "sql-app-get-user-safe",
            "file": "app.py",
            "function": "get_user_safe",
            "vulnerability_type": "sql_injection",
            "expected_vulnerable": False,
            "source_description": "parameterized query with ? placeholder",
            "sink_description": "conn.execute('SELECT ... WHERE id = ?', (user_id,))",
            "source_line": 23,
            "sink_line": 25,
        },
        # --------------------------------------------------- app.py: CMDi
        {
            "case_id": "cmd-app-run-command",
            "file": "app.py",
            "function": "run_command",
            "vulnerability_type": "command_injection",
            "expected_vulnerable": True,
            "source_description": "cmd parameter passed to shell",
            "sink_description": "subprocess.run(cmd, shell=True)",
            "source_line": 33,
            "sink_line": 34,
        },
        {
            "case_id": "cmd-app-run-command-safe",
            "file": "app.py",
            "function": "run_command_safe",
            "vulnerability_type": "command_injection",
            "expected_vulnerable": False,
            "source_description": "constant command string",
            "sink_description": "subprocess.run('ls -la', shell=True)",
            "source_line": 50,
            "sink_line": 51,
        },
        # --------------------------------------------------- app.py: SSRF
        {
            "case_id": "ssrf-app-fetch-url",
            "file": "app.py",
            "function": "fetch_url",
            "vulnerability_type": "ssrf",
            "expected_vulnerable": True,
            "source_description": "url parameter passed to requests",
            "sink_description": "requests.get(url, timeout=5)",
            "source_line": 37,
            "sink_line": 40,
        },
        {
            "case_id": "ssrf-app-fetch-safe",
            "file": "app.py",
            "function": "fetch_safe",
            "vulnerability_type": "ssrf",
            "expected_vulnerable": False,
            "source_description": "constant https URL",
            "sink_description": "requests.get('https://example.com')",
            "source_line": 44,
            "sink_line": 47,
        },
        # ----------------------------------------------------- db.py: SQLi
        {
            "case_id": "sql-db-execute",
            "file": "db.py",
            "function": "execute",
            "vulnerability_type": "sql_injection",
            "expected_vulnerable": True,
            "source_description": "sql parameter forwarded to connection",
            "sink_description": "self.connection.execute(sql)",
            "source_line": 14,
            "sink_line": 17,
        },
        {
            "case_id": "sql-db-query-users",
            "file": "db.py",
            "function": "query_users",
            "vulnerability_type": "sql_injection",
            "expected_vulnerable": True,
            "source_description": "user_id interpolated into SQL f-string",
            "sink_description": "self.execute(f'SELECT ... id = {user_id}')",
            "source_line": 19,
            "sink_line": 20,
        },
    ),
}

KNOWN_FIXTURES = frozenset(FIXTURE_GROUND_TRUTH)


def get_ground_truth(fixture: str) -> list[GroundTruthCase]:
    """Ground truth cases for a fixture; empty list when none is declared."""
    return list(FIXTURE_GROUND_TRUTH.get(fixture, []))


def vulnerable_cases(fixture: str) -> list[GroundTruthCase]:
    return [c for c in get_ground_truth(fixture) if c.expected_vulnerable]


def safe_cases(fixture: str) -> list[GroundTruthCase]:
    return [c for c in get_ground_truth(fixture) if not c.expected_vulnerable]