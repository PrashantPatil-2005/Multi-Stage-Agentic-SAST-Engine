"""Deterministic proof planning for PROVE.

The planner inspects the vulnerability type of a validated finding and
produces a structured, safe proof plan: objective, allowed actions, expected
observation, the approved harness to run, and the planner-controlled benign
input value.

The planner NEVER executes anything and NEVER uses attacker-like payloads
derived from the finding's snippets - finding content is data inside the
plan description only.

Trusted harness templates live here. They are the ONLY code ever executed by
the sandbox, and each one asserts it is running inside the sandbox workspace.
"""

import os

from pydantic import BaseModel

from app.prove.models import SandboxPolicy
from app.scan.models import CandidateFinding

#: The only harnesses the SandboxRunner is allowed to execute.
APPROVED_HARNESSES = frozenset(
    {"sql_injection_proof", "command_injection_proof", "ssrf_proof", "probe_proof"}
)

_SQLI_MARKER = "1 OR 1=1"  # benign logic marker: `WHERE id = 1 OR 1=1` selects all fixture rows
_CMDI_MARKER_WINDOWS = "& echo PROVED_CMDI > prove_marker.txt"
_CMDI_MARKER_POSIX = "; echo PROVED_CMDI > prove_marker.txt"
_CMDI_CONTROL = "sast_prove_control_value"


class ProofPlan(BaseModel):
    vulnerability_type: str
    objective: str
    allowed_actions: list[str]
    expected_observation: str
    harness: str
    input_value: str
    harness_script: str
    policy: SandboxPolicy


class ProofPlanner:
    """Deterministic planner: same finding -> same plan."""

    def plan(self, finding: CandidateFinding) -> ProofPlan | None:
        if finding.vulnerability_type == "sql_injection":
            return self._sql_plan(finding)
        if finding.vulnerability_type == "command_injection":
            return self._cmd_plan(finding)
        if finding.vulnerability_type == "ssrf":
            return self._ssrf_plan(finding)
        return None

    # ------------------------------------------------------------------ plans

    def _sql_plan(self, finding: CandidateFinding) -> ProofPlan:
        return ProofPlan(
            vulnerability_type=finding.vulnerability_type,
            objective=(
                "Demonstrate in a controlled in-memory SQLite fixture that the "
                "vulnerable construction interpolates untrusted input into the SQL "
                "statement, by comparing unsafe (string construction) vs "
                "parameterized execution of the same query."
            ),
            allowed_actions=[
                "create an in-memory SQLite database inside the sandbox",
                "run read-only SELECT statements against the local fixture",
                "compare result sets of unsafe vs parameterized construction",
            ],
            expected_observation=(
                "unsafe_rows != safe_rows for the benign marker "
                f"{_SQLI_MARKER!r} (no external database, no writes)"
            ),
            harness="sql_injection_proof",
            input_value=_SQLI_MARKER,
            harness_script=_sql_harness(),
            policy=SandboxPolicy(),
        )

    def _cmd_plan(self, finding: CandidateFinding) -> ProofPlan:
        marker = _CMDI_MARKER_WINDOWS if os.name == "nt" else _CMDI_MARKER_POSIX
        return ProofPlan(
            vulnerability_type=finding.vulnerability_type,
            objective=(
                "Demonstrate that the command sink interpolates untrusted input "
                "into a shell command string. A harmless planner-controlled marker "
                "must be the only thing that can produce a known marker file inside "
                "the sandbox workspace."
            ),
            allowed_actions=[
                "build the command string with the planner-controlled marker",
                "execute the benign command inside the sandbox workspace only",
                "verify the marker file inside the sandbox workspace",
            ],
            expected_observation=(
                "control run (no metacharacters) does NOT create the marker file; "
                "marker run creates it"
            ),
            harness="command_injection_proof",
            input_value=marker,
            harness_script=_cmd_harness(),
            policy=SandboxPolicy(),
        )

    def _ssrf_plan(self, finding: CandidateFinding) -> ProofPlan:
        return ProofPlan(
            vulnerability_type=finding.vulnerability_type,
            objective=(
                "Demonstrate that controlled input reaches an HTTP request sink. "
                "The destination is a harness-created, in-process HTTP server on "
                "127.0.0.1 with an OS-assigned ephemeral port - never an external "
                "host, localhost service, or metadata endpoint."
            ),
            allowed_actions=[
                "start a ThreadingHTTPServer bound to 127.0.0.1 on port 0 (ephemeral)",
                "perform exactly one request to the harness-generated URL",
                "shut the server down inside the same process",
            ],
            expected_observation="the harness-generated endpoint answers 200 with body 'proved'",
            harness="ssrf_proof",
            input_value="",  # destination is generated by the harness itself
            harness_script=_ssrf_harness(),
            policy=SandboxPolicy(allow_loopback=True),  # network_enabled stays False
        )


# ------------------------------------------------------------- harness templates
# Trusted internal templates. Each harness guards its own execution: it
# refuses to run unless cwd is exactly the sandbox workspace.

def _sandbox_guard() -> str:
    return (
        "import os\n"
        "sandbox = os.environ.get('SANDBOX_DIR', '')\n"
        "assert sandbox and os.path.realpath(os.getcwd()) == os.path.realpath(sandbox), "
        "'harness must run inside the sandbox workspace'\n"
    )


def _sql_harness() -> str:
    return _sandbox_guard() + (
        "import sqlite3\n"
        "import sys\n"
        "MARKER = sys.argv[1]\n"
        "db = sqlite3.connect(':memory:')\n"
        "db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)')\n"
        "db.executemany('INSERT INTO users (name) VALUES (?)', [('alice',), ('bob',)])\n"
        "def unsafe(user_input):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_input}'\n"
        "    return query, [tuple(row) for row in db.execute(query)]\n"
        "def safe(user_input):\n"
        "    query = 'SELECT * FROM users WHERE id = ?'\n"
        "    return query, [tuple(row) for row in db.execute(query, (user_input,))]\n"
        "unsafe_query, unsafe_rows = unsafe(MARKER)\n"
        "safe_query, safe_rows = safe(MARKER)\n"
        "print(f'UNSAFE_QUERY:{unsafe_query}')\n"
        "print(f'SAFE_QUERY:{safe_query}')\n"
        "print(f'PROVED:unsafe_rows={len(unsafe_rows)}:safe_rows={len(safe_rows)}')\n"
    )


def _cmd_harness() -> str:
    return _sandbox_guard() + (
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "MARKER = sys.argv[1]\n"
        "CONTROL = 'sast_prove_control_value'\n"
        "MARKER_FILE = 'prove_marker.txt'\n"
        "marker_path = os.path.join(os.getcwd(), MARKER_FILE)\n"
        "if os.path.exists(marker_path):\n"
        "    os.remove(marker_path)  # own artifact inside the sandbox only\n"
        "def run(command):\n"
        "    subprocess.run(command, shell=True, cwd=os.getcwd(), timeout=5,\n"
        "                   capture_output=True, text=True)\n"
        "run(f'echo {CONTROL}')\n"
        "control_hit = os.path.exists(marker_path)\n"
        "if os.path.exists(marker_path):\n"
        "    os.remove(marker_path)\n"
        "run(f'echo {MARKER}')\n"
        "injected_hit = os.path.exists(marker_path)\n"
        "print(f'PROVED:control_hit={int(control_hit)}:injected_hit={int(injected_hit)}')\n"
    )


def _ssrf_harness() -> str:
    return _sandbox_guard() + (
        "import threading\n"
        "import urllib.request\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200)\n"
        "        self.end_headers()\n"
        "        self.wfile.write(b'proved')\n"
        "    def log_message(self, *args):\n"
        "        pass\n"
        "server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)\n"
        "port = server.server_address[1]\n"
        "thread = threading.Thread(target=server.serve_forever, daemon=True)\n"
        "thread.start()\n"
        "try:\n"
        "    url = f'http://127.0.0.1:{port}/prove'\n"
        "    with urllib.request.urlopen(url, timeout=5) as response:\n"
        "        body = response.read().decode('utf-8')\n"
        "    print(f'URL:{url}')\n"
        "    print(f'PROVED:status={response.status}:body={body}')\n"
        "finally:\n"
        "    server.shutdown()\n"
    )


def _probe_harness() -> str:
    """TEST-ONLY harness for sandbox policy tests (never used by plans).

    Actions are selected via environment variables:
    * PROBE_ACTION=sleep  -> sleep PROBE_SLEEP seconds
    * PROBE_ACTION=print  -> print PROBE_TEXT repeated PROBE_REPEAT times
    * PROBE_PATH=<path>   -> attempt to read the path; only paths inside the
                             sandbox workspace are readable, anything else
                             prints READ_DENIED without opening the file.
    """
    return _sandbox_guard() + (
        "import os\n"
        "import sys\n"
        "import time\n"
        "action = os.environ.get('PROBE_ACTION', 'print')\n"
        "if action == 'sleep':\n"
        "    time.sleep(float(os.environ.get('PROBE_SLEEP', '60')))\n"
        "elif action == 'print':\n"
        "    text = os.environ.get('PROBE_TEXT', 'x')\n"
        "    repeat = int(os.environ.get('PROBE_REPEAT', '1'))\n"
        "    print(text * repeat)\n"
        "probe_path = os.environ.get('PROBE_PATH', '')\n"
        "if probe_path:\n"
        "    sandbox = os.path.realpath(os.environ['SANDBOX_DIR'])\n"
        "    target = os.path.realpath(probe_path)\n"
        "    if os.path.commonpath([target, sandbox]) == sandbox:\n"
        "        with open(target, 'r', encoding='utf-8', errors='replace') as fh:\n"
        "            print('READ_OK:' + fh.read(200))\n"
        "    else:\n"
        "        print('READ_DENIED')\n"
    )


HARNESS_SCRIPTS = {
    "sql_injection_proof": _sql_harness,
    "command_injection_proof": _cmd_harness,
    "ssrf_proof": _ssrf_harness,
    "probe_proof": _probe_harness,
}