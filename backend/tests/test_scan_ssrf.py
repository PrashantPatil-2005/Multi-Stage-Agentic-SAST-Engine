"""SCAN stage tests for SSRF taint analysis."""

import urllib.request
from unittest import mock

from tests.scan_test_helpers import scan_fixture_files, scan_sources


# ------------------------------------------------------------ direct injection

def test_requests_get_direct_ssrf():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.vulnerability_type == "ssrf"
    assert f.severity == "high"
    assert f.status == "candidate"
    assert f.source.kind == "request_param"
    assert f.sink.kind == "http_request"
    assert f.confidence == 0.9


def test_requests_post_direct_ssrf():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.post(url, data={'a': 1})\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].sink.line == 3


def test_requests_put_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.put(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_requests_delete_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.delete(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_requests_patch_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.patch(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_requests_head_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.head(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_requests_options_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.options(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_requests_request_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.request('GET', url)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].sink.line == 3


def test_httpx_get_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    httpx.get(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_httpx_post_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    httpx.post(url, json={'a': 1})\n"
            )
        }
    )
    assert report.summary.total == 1


def test_httpx_request_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    httpx.request('POST', url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_urllib_request_urlopen_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    urllib.request.urlopen(url)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_url_keyword_argument():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url=url)\n"
                "    httpx.get(url=url)\n"
                "    urllib.request.urlopen(url=url)\n"
            )
        }
    )
    assert report.summary.total == 3


# ------------------------------------------------------------ propagation

def test_assignment_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    target = url\n"
                "    requests.get(target)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.source.line == 2
    assert f.sink.line == 4
    assert [s.step_type for s in f.taint_path] == [
        "source",
        "assignment",
        "assignment",
        "sink",
    ]


def test_fstring_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    host = request.args.get('host')\n"
                "    url = f'https://{host}/api'\n"
                "    requests.get(url)\n"
            )
        }
    )
    assert report.summary.total == 1
    types = [s.step_type for s in report.findings[0].taint_path]
    assert types == ["source", "assignment", "string_construction", "sink"]


def test_string_concatenation_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    target = 'https://example.com/?next=' + url\n"
                "    requests.get(target)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.source.line == 2
    assert f.sink.line == 4


def test_format_method_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    target = 'https://example.com/{}'.format(url)\n"
                "    requests.get(target)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_function_parameter_source():
    report = scan_sources(
        {
            "app.py": (
                "def fetch_url(url: str):\n"
                "    return requests.get(url)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.source.kind == "function_param"
    assert f.source.line == 1
    assert f.sink.line == 2
    assert f.confidence == 0.7


# ------------------------------------------------------------ combined checks

def test_multiple_ssrf_findings():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    a = request.args.get('a')\n"
                "    b = request.args.get('b')\n"
                "    requests.get(a)\n"
                "    requests.post(b)\n"
            )
        }
    )
    assert report.summary.total == 2
    assert report.summary.by_type["ssrf"] == 2


def test_correct_source_line():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url)\n"
            )
        }
    )
    assert report.findings[0].source.line == 2


def test_correct_sink_line():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url)\n"
            )
        }
    )
    assert report.findings[0].sink.line == 3


def test_correct_taint_path():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url)\n"
            )
        }
    )
    steps = report.findings[0].taint_path
    assert [s.step_type for s in steps] == ["source", "assignment", "sink"]
    assert steps[0].line == 2
    assert steps[-1].line == 3
    assert steps[-1].snippet == "requests.get(url)"


def test_evidence_generation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = request.args.get('url')\n"
                "    requests.get(url)\n"
            )
        }
    )
    ev = report.findings[0].evidence
    assert ev.source_snippet == "request.args.get('url')"
    assert ev.sink_snippet == "requests.get(url)"
    assert ev.relevant_lines == [2, 3]
    assert ev.sanitizer_observations == ["no sanitizer observed at sink"]
    assert len(ev.taint_path) == 3


# ------------------------------------------------------------ safe cases

def test_constant_url_ignored():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    requests.get('https://example.com')\n"
            )
        }
    )
    assert report.summary.total == 0


def test_constant_url_variable_ignored():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    url = 'https://example.com/api'\n"
                "    requests.get(url)\n"
            )
        }
    )
    assert report.summary.total == 0


def test_no_outbound_network_request_performed():
    sources = {
        "app.py": (
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    target = 'http://127.0.0.1:9999/steal?u=' + url\n"
            "    requests.get(target)\n"
        )
    }
    with mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("network!")), mock.patch(
        "socket.socket"
    ) as fake_socket:
        report = scan_sources(sources)
        assert report.summary.total == 1
        assert report.findings[0].sink.kind == "http_request"
        fake_socket.assert_not_called()


def test_deterministic_results():
    sources = {
        "app.py": (
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    requests.get(url)\n"
        )
    }
    first = scan_sources(sources)
    second = scan_sources(sources)
    assert [f.model_dump() for f in first.findings] == [
        f.model_dump() for f in second.findings
    ]


# ------------------------------------------------------------ fixture / regressions

def test_fixture_fetch_url_detected():
    report = scan_fixture_files("app.py")
    ssrf = next(f for f in report.findings if f.vulnerability_type == "ssrf")
    assert ssrf.source.line == 37  # def fetch_url(url: str) -> str:
    assert ssrf.source.kind == "function_param"
    assert ssrf.sink.line == 40  # response = requests.get(url, timeout=5)
    assert ssrf.sink.snippet == "requests.get(url, timeout=5)"


def test_fixture_fetch_safe_ignored():
    report = scan_fixture_files("app.py")
    assert report.summary.by_type.get("ssrf", 0) == 1  # only fetch_url
    # the constant-URL helper must not produce a finding
    ssrf_lines = [f.sink.line for f in report.findings if f.vulnerability_type == "ssrf"]
    assert ssrf_lines == [40]


def test_sql_injection_tests_still_pass():
    report = scan_fixture_files("app.py", "db.py")
    assert report.summary.by_type["sql_injection"] == 3
    assert report.summary.by_type["command_injection"] == 1
    assert report.summary.by_type["ssrf"] == 1
    assert report.summary.total == 5
    sql = next(f for f in report.findings if f.vulnerability_type == "sql_injection")
    assert sql.sink.line == 15  # conn.execute(query)


def test_command_injection_tests_still_pass():
    report = scan_fixture_files("app.py")
    cmd = next(f for f in report.findings if f.vulnerability_type == "command_injection")
    assert cmd.sink.line == 34  # subprocess.run(cmd, shell=True)
    assert cmd.sink.snippet == "subprocess.run(cmd, shell=True)"
