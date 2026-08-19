"""SCAN stage tests for deserialization vulnerability detection."""

from tests.scan_test_helpers import scan_sources


# ──────────────────────────────────── pickle

def test_pickle_loads_direct_finding():
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = pickle.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.source.kind == "request_param"
    assert f.sink.kind == "pickle_loads"


def test_pickle_load_finding():
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = pickle.load(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].sink.kind == "pickle_load"


def test_cpickle_loads_finding():
    report = scan_sources(
        {
            "app.py": (
                "import cPickle\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = cPickle.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1


# ──────────────────────────────────── marshal

def test_marshal_loads_finding():
    report = scan_sources(
        {
            "app.py": (
                "import marshal\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = marshal.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].sink.kind == "marshal_loads"


# ──────────────────────────────────── yaml

def test_yaml_load_no_loader_finding():
    report = scan_sources(
        {
            "app.py": (
                "import yaml\n"
                "def handler():\n"
                "    data = request.args.get('config')\n"
                "    obj = yaml.load(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].sink.kind == "yaml_load"


def test_yaml_load_with_safeloader_no_finding():
    report = scan_sources(
        {
            "app.py": (
                "import yaml\n"
                "def handler():\n"
                "    data = request.args.get('config')\n"
                "    obj = yaml.load(data, Loader=yaml.SafeLoader)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 0


def test_yaml_safe_load_no_finding():
    report = scan_sources(
        {
            "app.py": (
                "import yaml\n"
                "def handler():\n"
                "    data = request.args.get('config')\n"
                "    obj = yaml.safe_load(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 0


# ──────────────────────────────────── shelve

def test_shelve_open_finding():
    report = scan_sources(
        {
            "app.py": (
                "import shelve\n"
                "def handler():\n"
                "    name = request.args.get('db')\n"
                "    db = shelve.open(name)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].sink.kind == "shelve_open"


# ──────────────────────────────────── jsonpickle

def test_jsonpickle_decode_finding():
    report = scan_sources(
        {
            "app.py": (
                "import jsonpickle\n"
                "def handler():\n"
                "    data = request.args.get('obj')\n"
                "    obj = jsonpickle.decode(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].sink.kind == "jsonpickle_decode"


# ──────────────────────────────────── safe cases

def test_json_loads_no_finding():
    """json.loads is safe and should never be flagged."""
    report = scan_sources(
        {
            "app.py": (
                "import json\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = json.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 0


def test_no_sink_no_finding():
    """No deserialization API → no finding."""
    report = scan_sources(
        {
            "app.py": (
                "def handler():\n"
                "    data = request.args.get('x')\n"
                "    result = data.upper()\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 0


def test_constant_no_finding():
    """Constant input → no deserialization finding."""
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    obj = pickle.loads(b'constant data')\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 0


# ──────────────────────────────────── param source

def test_param_source_finding():
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def process(data):\n"
                "    obj = pickle.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].source.kind == "function_param"
    assert findings[0].confidence == 0.7


def test_request_source_finding():
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    data = request.json\n"
                "    obj = pickle.loads(data)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    assert findings[0].source.kind == "request_json"
    assert findings[0].confidence == 0.9


# ──────────────────────────────────── taint path

def test_taint_path_through_assignment():
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    raw = request.args.get('data')\n"
                "    payload = raw\n"
                "    obj = pickle.loads(payload)\n"
            )
        }
    )
    findings = [f for f in report.findings if f.vulnerability_type == "deserialization"]
    assert len(findings) == 1
    step_types = [s.step_type for s in findings[0].taint_path]
    assert "source" in step_types
    assert "sink" in step_types


# ──────────────────────────────────── multiple vuln types

def test_deserialization_with_sql_injection():
    """Both deserialization and SQL injection should be detected."""
    report = scan_sources(
        {
            "app.py": (
                "import pickle\n"
                "def handler():\n"
                "    data = request.args.get('payload')\n"
                "    obj = pickle.loads(data)\n"
                "    query = f'SELECT * FROM t WHERE id={data}'\n"
                "    cursor.execute(query)\n"
            )
        }
    )
    assert report.summary.by_type.get("deserialization", 0) == 1
    assert report.summary.by_type.get("sql_injection", 0) == 1
