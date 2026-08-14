"""SCAN stage tests for command injection taint analysis."""

from tests.scan_test_helpers import scan_fixture_files, scan_sources


# ------------------------------------------------------------ direct injection

def test_os_system_direct_injection():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.vulnerability_type == "command_injection"
    assert f.severity == "high"
    assert f.status == "candidate"
    assert f.source.kind == "request_param"
    assert f.sink.kind == "command_exec"
    assert f.confidence == 0.9


def test_subprocess_run_direct_injection():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.run(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].vulnerability_type == "command_injection"


def test_subprocess_call_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.call(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].sink.kind == "command_exec"


def test_subprocess_popen_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.Popen(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    assert report.findings[0].sink.line == 3


def test_subprocess_check_call_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.check_call(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_subprocess_check_output_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.check_output(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_os_popen_detected():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.popen(cmd)\n"
            )
        }
    )
    assert report.summary.total == 1


# ------------------------------------------------------------ propagation

def test_assignment_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    command = cmd\n"
                "    os.system(command)\n"
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
                "    cmd = request.args.get('cmd')\n"
                "    subprocess.Popen(f\"bash -c '{cmd}'\", shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.sink.line == 3
    types = [s.step_type for s in f.taint_path]
    assert types == ["source", "assignment", "string_construction", "sink"]


def test_string_concatenation_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    host = request.args.get('host')\n"
                "    command = 'ping ' + host\n"
                "    subprocess.run(command, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.source.line == 2
    assert f.sink.line == 4
    types = [s.step_type for s in f.taint_path]
    assert types == ["source", "assignment", "string_construction", "sink"]


def test_format_method_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    command = 'bash -c {}'.format(cmd)\n"
                "    os.system(command)\n"
            )
        }
    )
    assert report.summary.total == 1


def test_percent_formatting_propagation():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    command = 'ping %s' % cmd\n"
                "    os.system(command)\n"
            )
        }
    )
    assert report.summary.total == 1


# ------------------------------------------------------------ parameter source

def test_function_parameter_source():
    report = scan_sources(
        {
            "app.py": (
                "def run_command(cmd: str) -> None:\n"
                "    subprocess.run(cmd, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 1
    f = report.findings[0]
    assert f.source.kind == "function_param"
    assert f.source.line == 1
    assert f.sink.line == 2
    assert f.confidence == 0.7


# ------------------------------------------------------------ safe cases

def test_safe_constant_command_not_flagged():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    subprocess.run('ls -la')\n"
                "    os.system('echo hello')\n"
            )
        }
    )
    assert report.summary.total == 0


def test_safe_list_form_subprocess_not_flagged():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    host = request.args.get('host')\n"
                "    subprocess.run(['ping', '-c', '1', host])\n"
                "    subprocess.run(['ls', '-la'])\n"
            )
        }
    )
    assert report.summary.total == 0


def test_shell_true_alone_is_not_the_vulnerability():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    subprocess.run('ls -la', shell=True)\n"
            )
        }
    )
    assert report.summary.total == 0


# ------------------------------------------------------------ combined checks

def test_multiple_command_injection_findings():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    a = request.args.get('a')\n"
                "    b = request.args.get('b')\n"
                "    os.system(a)\n"
                "    subprocess.run(b, shell=True)\n"
            )
        }
    )
    assert report.summary.total == 2
    assert report.summary.by_type["command_injection"] == 2


def test_correct_source_and_sink_lines():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n"
            )
        }
    )
    f = report.findings[0]
    assert f.source.file == "app.py"
    assert f.source.line == 2
    assert f.sink.file == "app.py"
    assert f.sink.line == 3


def test_correct_taint_path():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n"
            )
        }
    )
    f = report.findings[0]
    steps = f.taint_path
    assert [s.step_type for s in steps] == ["source", "assignment", "sink"]
    assert steps[0].line == 2
    assert steps[-1].line == 3
    assert steps[-1].snippet == "os.system(cmd)"


def test_evidence_fields():
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    cmd = request.args.get('cmd')\n"
                "    os.system(cmd)\n"
            )
        }
    )
    ev = report.findings[0].evidence
    assert ev.source_snippet == "request.args.get('cmd')"
    assert ev.sink_snippet == "os.system(cmd)"
    assert ev.relevant_lines == [2, 3]
    assert ev.sanitizer_observations == ["no sanitizer observed at sink"]
    assert len(ev.taint_path) == 3


def test_deterministic_results():
    sources = {
        "app.py": (
            "def handler():\n"
            "    cmd = request.args.get('cmd')\n"
            "    os.system(cmd)\n"
        )
    }
    first = scan_sources(sources)
    second = scan_sources(sources)
    assert [f.model_dump() for f in first.findings] == [
        f.model_dump() for f in second.findings
    ]


def test_sql_tests_still_pass_alongside():
    report = scan_fixture_files("app.py")
    by_type = report.summary.by_type
    assert by_type == {
        "sql_injection": 1,
        "command_injection": 1,
        "ssrf": 1,
    }
    sql = next(f for f in report.findings if f.vulnerability_type == "sql_injection")
    cmd = next(f for f in report.findings if f.vulnerability_type == "command_injection")
    assert sql.sink.line == 15  # conn.execute(query)
    assert cmd.source.line == 33  # def run_command(cmd: str) -> None:
    assert cmd.sink.line == 34  # subprocess.run(cmd, shell=True)
    assert cmd.sink.snippet == "subprocess.run(cmd, shell=True)"
