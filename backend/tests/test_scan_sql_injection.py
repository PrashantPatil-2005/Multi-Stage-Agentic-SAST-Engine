"""SCAN stage tests for SQL injection taint analysis."""

from datetime import datetime, timezone

from app.core.contracts import CodeModel
from app.scan.service import ScanService
from tests.scan_test_helpers import scan_fixture_files, scan_sources


# --------------------------------------------------------------------------- basic findings


def test_direct_sql_injection_in_execute():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.vulnerability_type == "sql_injection"
    assert f.severity == "high"
    assert f.status == "candidate"
    assert f.source.kind == "request_param"
    assert f.sink.line == 3
    assert f.confidence == 0.9


def test_sql_injection_through_assignment():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    query = \"SELECT * FROM users WHERE id=\" + user_id\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.sink.line == 4
    assert f.source.line == 2
    # path: source, assignment, string_construction, sink -> 2 intermediates -> no penalty
    assert f.confidence == 0.9


def test_sql_injection_long_chain_lowers_confidence():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    query = 'SELECT * FROM users WHERE id=' + user_id\n"
                "    final = query + ' ORDER BY 1'\n"
                "    cursor.execute(final)\n"
            )
        }
    )
    assert report.summary.total == 1
    # path: source, assignment, string_construction, string_construction, sink
    # -> 3 intermediates -> penalty of 0.1
    assert report.findings[0].confidence == 0.8


def test_sql_injection_through_fstring():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.sink.line == 4


def test_sql_injection_through_format_method():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    query = \"SELECT * FROM users WHERE id={}\".format(user_id)\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_sql_injection_through_percent_formatting():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    query = \"SELECT * FROM users WHERE id=%s\" % user_id\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_sql_injection_via_subscript_source():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args['id']\n"
                "    query = \"SELECT * FROM users WHERE id=\" + user_id\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].source.kind == "request_param"


def test_sql_injection_via_request_json():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    data = request.json\n"
                "    query = f\"SELECT * FROM users WHERE id={data['id']}\"\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].source.kind == "request_json"


def test_sql_injection_via_form_source():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.form.get('user')\n"
                "    cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
            )
        }
    )
    assert report.summary.total == 1


# ------------------------------------------------------------------------- safe cases


def test_safe_parameterized_query_no_finding():
    report = scan_sources(
        {
            "app.py": (
                "def get_user_safe(user_id: int):\n"
                "    cursor.execute(\n"
                "        'SELECT * FROM users WHERE id = ?',\n"
                "        (user_id,)\n"
                "    )\n"
            )
        }
    )
    assert report.summary.total == 0


def test_constant_query_no_finding():
    report = scan_sources(
        {
            "app.py": 'def handler():\n    cursor.execute("SELECT * FROM users WHERE id = 1")\n'
        }
    )
    assert report.summary.total == 0


def test_parameterized_with_dict_no_finding():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    user_id = request.args.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id=:uid', {'uid': user_id})\n"
            )
        }
    )
    assert report.summary.total == 0


def test_no_sql_sink_no_finding():
    # no SQL sink, but the command injection rule SHOULD flag subprocess.run
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.run(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.by_type.get("sql_injection", 0) == 0
    assert report.summary.by_type["command_injection"] == 1


def test_param_without_sink_no_finding():
    report = scan_sources({"app.py": "def do_stuff(user_id: str):\n    return user_id.upper()\n"})
    assert report.summary.total == 0


def test_executemany_sink_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    rows = request.json\n"
                "    cursor.executemany('INSERT INTO t VALUES (?)', rows)\n"
            )
        }
    )
    assert report.summary.total == 0  # sanitized (params provided)


# ---------------------------------------------------------------------- fixture


def test_fixture_app_multiple_findings():
    report = scan_fixture_files("app.py", "db.py")
    assert report.summary.total == 5
    assert report.summary.by_type["sql_injection"] == 3
    assert report.summary.by_type["command_injection"] == 1
    assert report.summary.by_type["ssrf"] == 1
    files = {f.sink.file for f in report.findings}
    assert files == {"app.py", "db.py"}


def test_fixture_get_user_finding_file_and_line():
    report = scan_fixture_files("app.py")
    f = next(x for x in report.findings if x.vulnerability_type == "sql_injection")
    assert f.source.file == "app.py"
    assert f.source.line == 12  # def get_user(...)
    assert f.sink.file == "app.py"
    assert f.sink.line == 15  # cursor = conn.execute(query)
    assert f.source.kind == "function_param"
    assert f.confidence == 0.7


def test_fixture_get_user_safe_no_false_positive():
    report = scan_fixture_files("app.py")
    sql = [f for f in report.findings if f.vulnerability_type == "sql_injection"]
    assert sql  # the SQLi finding still exists
    assert all(f.sink.line != 25 for f in sql)


def test_fixture_taint_path_steps():
    report = scan_fixture_files("app.py")
    f = next(x for x in report.findings if x.vulnerability_type == "sql_injection")
    types = [s.step_type for s in f.taint_path]
    assert types == ["source", "string_construction", "sink"]
    assert f.taint_path[0].snippet == "def get_user(user_id: str) -> dict:"
    assert f.taint_path[1].snippet.startswith("query = f")
    assert f.taint_path[2].snippet.startswith("conn.execute(query)")


def test_fixture_evidence_fields():
    report = scan_fixture_files("app.py")
    f = next(x for x in report.findings if x.vulnerability_type == "sql_injection")
    ev = f.evidence
    assert ev.source_snippet == "def get_user(user_id: str) -> dict:"
    assert ev.sink_snippet.startswith("conn.execute(query)")
    assert ev.relevant_lines == [12, 14, 15]
    assert ev.sanitizer_observations == ["no sanitizer observed at sink"]
    assert len(ev.taint_path) == 3


def test_fixture_ignores_poison_and_bad_syntax_files():
    report = scan_fixture_files("poison.py", "bad_syntax.py")
    assert report.summary.total == 0  # no SQL sinks; parse errors skipped safely
    assert report.scanned_file_count == 2


# ----------------------------------------------------------------- misc checks


def test_scan_report_structure():
    report = scan_fixture_files("app.py")
    assert report.id
    assert report.summary.total == len(report.findings)
    assert report.summary.by_type == {
        "sql_injection": 1,
        "command_injection": 1,
        "ssrf": 1,
    }
    assert report.scanned_file_count == 1
    assert any(s.qualified_name == "get_user" for s in report.function_summaries)


def test_function_summaries_recorded():
    report = scan_fixture_files("db.py")
    by_name = {s.qualified_name: s for s in report.function_summaries}
    assert "Database.execute" in by_name
    assert "sql" in by_name["Database.execute"].tainted_params
    assert "Database.query_users" in by_name
    assert by_name["Database.query_users"].sinks  # reached a sink


def test_scan_is_deterministic():
    sources = {
        "app.py": (
            "def handler():\n"
            "    user_id = request.args.get('id')\n"
            "    query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
            "    cursor.execute(query)\n"
        )
    }
    first = scan_sources(sources)
    second = scan_sources(sources)
    assert [f.model_dump() for f in first.findings] == [f.model_dump() for f in second.findings]


def test_scan_empty_model():
    model = CodeModel(
        language="python",
        files=[],
        module_map={},
        function_index=[],
        built_at=datetime.now(timezone.utc),
    )
    report = ScanService().scan(model)
    assert report.summary.total == 0
    assert report.scanned_file_count == 0
