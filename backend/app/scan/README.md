# SCAN stage — taint analysis (SQL injection)

Deterministic, rule-driven static taint analysis over the `CodeModel`
produced by PREPARE. No LLM, no regex-only detection, no code execution:
the engine reasons about **source → propagation → sink** using the Python
AST extracted from each file's actual source.

## Scan runs (lineage)

Every execution of `POST /api/projects/{id}/scan` records a durable
`ScanRun` (see `app/scan/run_models.py`) with:

- run status (`running` → `completed`/`failed`), start/end timestamps, real
  counts (`scanned_file_count`, `total_findings`) and a persisted `error`
  when a stage fails;
- one `ScanStageRun` per pipeline stage, in pipeline order: PREPARE,
  SCAN, DEDUPLICATE, RISK, SLA, VALIDATE, PROVE, APPROVAL. The scan route
  itself records PREPARE and SCAN; every other stage stays `pending` until
  its own user-triggered endpoint executes it with an explicit
  `scan_run_id` context (see "Stage executions" below) — nothing is
  chained automatically;
- explicit finding lineage (`scan_findings`): each finding id produced by
  the run maps back to `project_id → scan_run_id → finding_id`. Rescanning
  the same project creates a new run; deterministic finding ids may repeat
  across runs without duplicating Finding records.

The scan executes synchronously; the run record is terminal when the route
returns. History is served by `GET /api/projects/{id}/scans`,
`GET /api/scans/{scan_run_id}` and `GET /api/scans/{scan_run_id}/findings`,
and survives backend restarts (SQLite, see `app/db/persistence.py`).

## Stage executions (Phases 14J/14K)

The pipeline stages are registered per run in order: PREPARE, SCAN,
DEDUPLICATE, RISK, SLA, VALIDATE, PROVE, APPROVAL. PREPARE and SCAN are
recorded by the scan route itself; the remaining stages are user-triggered
per-finding / per-repository endpoints, so their stage records stay
`pending` unless an explicit `scan_run_id` context is supplied. The optional
body field `{"scan_run_id": "<real scan run id>"}` is accepted by
`POST /api/deduplicate`, `POST /api/findings/{id}/risk`,
`POST /api/findings/{id}/sla`, `POST /api/findings/{id}/sla/check`,
`POST /api/findings/{id}/validate` (alongside `provider`),
`POST /api/findings/{id}/prove` and `POST /api/findings/{id}/approval`
(alongside `action`/`requested_by`):

- the backend validates the context — the run must exist (404) **and** its
explicit `scan_findings` lineage must produce the finding(s) (400
otherwise); cross-project fabrication is impossible because membership is
the persisted relationship, never timestamps/paths/ordering;
- the stage is then recorded as an explicit execution:
  `pending → running → completed` (or `failed` with the error persisted);
- history is append-only (`ScanStageExecution`): every call adds a record,
  so retrying a failed stage keeps the failed attempt and adds a new one;
- clients that omit `scan_run_id` behave exactly as before — the action
  runs with no stage record and no fabricated completion.

Stage semantics (truthful mapping, never fabricated):

- **PREPARE**: recorded `completed` (1 execution) when a run is created — a
  scan run can only exist for an already-prepared project; its timestamps
  use the project's real prepare time (`created_at`);
- **SCAN**: `completed` on report success, `failed` on scanner exception;
- **DEDUPLICATE**: `completed` when the dedup POST succeeds (including a
  legitimately empty result); no record when findings are missing (404);
- **RISK / SLA**: `completed` on a successful per-finding action;
- **VALIDATE**: `completed` on any successful validation API execution (the
  verdict — true_positive/false_positive/uncertain — does not change this);
  `failed` on exception, including provider configuration failure (503);
- **PROVE**: `completed` for `verified` / `not_verified` / `blocked` — the
  proof execution itself completed; `failed` for a returned
  `ProofResult(status="error")` (sandbox timeout, harness failure) and for
  a gate rejection (409, verdict not true_positive);
- **APPROVAL**: the request stores its `scan_run_id` and every decision
  (approve/reject/request-changes/resubmit) inherits it — the reviewer
  never resends the run. `completed` for a successful request or decision;
  `failed` for a gate rejection (409) or invalid transition (409).

`completed` means the last recorded execution of the stage succeeded;
`execution_count` counts every recorded execution (SCAN = 1 per scan;
DEDUPLICATE = 1 per dedup POST; RISK/SLA = 1 per per-finding action;
VALIDATE/PROVE = 1 per action; APPROVAL = 1 per request/decision). A stage
never auto-runs: one action records one execution and no downstream stage
is ever triggered. The background SLA evaluator updates SLA records only
and can never mark any scan-run stage as executed.

`GET /api/scans/{scan_run_id}` exposes both the stage statuses and the full
`executions` history, all persisted and restored on restart.

## Finding identity

Finding ids are deterministic and **project-scoped**:
`sha256(project_id | vulnerability_type | file | source_line | sink_line)`.
Rescanning the same project therefore yields the same ids (idempotent),
while two repositories with identical vulnerable file/line structures
produce distinct ids and never collide in the shared finding store.
The `project_id` is taken from the scan request (falling back to the
`CodeModel.project_id` when the service is called directly). The
cross-repository dedup fingerprint is deliberately separate — it is
structural only (see `backend/app/dedup/README.md`) and is unaffected by
the project-scoped id.

## Rules

- [SQL injection](#sql-injection) — `backend/app/scan/rules/sql_injection.py`
- [Command injection](#command-injection) — `backend/app/scan/rules/command_injection.py`
- [SSRF](#ssrf) — `backend/app/scan/rules/ssrf.py`

Each rule implements the `ScanRule` contract (`is_source`, `match_sink`,
`is_sanitized`, `sink_expression`, `confidence`, `poison_params`) and is
driven by the same `TaintEngine`. Shared logic (request-object sources,
confidence scoring) lives in `backend/app/scan/rules/common.py`.

## How taint analysis works

Per file, per function, the engine performs a forward, statement-order walk
maintaining a taint map: `variable name -> {provenance steps, source kind}`.
Every time a variable is assigned from a tainted expression it inherits the
full provenance path back to its source, so by the time a value reaches a
sink the engine can print the entire data-flow chain.

Control flow is handled conservatively: branches and loops are analyzed
separately and their tainted variables merged (a sound over-approximation).
Nested functions and methods are analyzed with a fresh taint state.

```
request.args.get("id")          source
        ↓
user_id                         assignment
        ↓
query = f"SELECT ... {user_id}" string_construction
        ↓
cursor.execute(query)           sink
```

## Sources (shared)

Recognized user-controlled inputs (Flask-style `request` object):

- `request.args.get(...)`, `request.args[...]`
- `request.form.get(...)`, `request.form[...]`
- `request.values.get(...)`, `request.values[...]`
- `request.json` (and subscripts of it, e.g. `request.json["id"]`)
- `request.cookies[...]`, `request.headers[...]` and `.get(...)` forms

In addition, **function parameters are poisoned**: every parameter (except
`self`/`cls`) enters a function tainted. A candidate is only created when a
poisoned parameter can be traced into a matching sink — parameters alone
never produce findings. This is a deliberately conservative choice: the
VALIDATE stage will judge exploitability. `get_user(user_id)` is flagged
while `fetch_url(url)` is not, because it contains no SQL sink.

## SQL sinks

Calls of `execute` / `executemany` / `executescript` on recognizable
database objects:

- `cursor.execute(...)`, `conn.execute(...)`, `connection.execute(...)`
- `db.execute(...)`, `database.execute(...)`, `engine.execute(...)`,
  `session.execute(...)`
- `self.execute(...)` / `self.connection.execute(...)` inside a class whose
  methods reach a DB handle (heuristic; object name matching)

The first positional argument is the SQL statement.

## Propagation rules

Taint propagates through:

- assignments (including annotated and augmented)
- string construction: f-strings (`JoinedStr`), `+` concatenation,
  `%` formatting (`BinOp Mod`), `.format(...)`
- `str(...)`, `repr(...)`, `bytes(...)` wrappers
- attribute / subscript access on tainted values (`data["id"]`, `user.name`)
- collection literals containing tainted elements
- loop variables (`for x in <tainted iterable>`)
- augmented assignment (`query += user_id`)

Taint does NOT flow through unknown function calls (no cross-function
resolution yet) and does not mark boolean expressions (`==`, `in`, ...).

## Sanitization rules

A sink call is considered sanitized — and produces no finding — when it
supplies query parameters:

- a second positional argument (`execute(sql, (user_id,))`, `execute(sql, {...})`)
- a `parameters=` / `params=` keyword argument

A literal `None` as the parameters value does NOT count as sanitization.
Custom sanitizer functions are deliberately NOT trusted.

## Command injection

`backend/app/scan/rules/command_injection.py`

### Sources

Identical to the SQL injection rule: Flask-style `request` objects
(`request.args` / `form` / `values` / `json` / `cookies` / `headers`) plus
poisoned function parameters. Logic is shared via `rules/common.py`.

### Sinks

Python command execution APIs — the **first positional argument** is the
command:

| API | Kind |
|---|---|
| `os.system(...)` | `os_system` |
| `os.popen(...)` | `os_popen` |
| `subprocess.run(...)` | `subprocess_run` |
| `subprocess.call(...)` | `subprocess_call` |
| `subprocess.Popen(...)` | `subprocess_popen` |
| `subprocess.check_call(...)` | `subprocess_check_call` |
| `subprocess.check_output(...)` | `subprocess_check_output` |

Sink matching is exact on the dotted name (`ast.unparse` of the call
function), so `import subprocess as sp; sp.run(cmd)` and
`from subprocess import run; run(cmd)` are currently missed.

### The vulnerability is the data, not the flag

`shell=True` alone is never a finding, and constant commands
(`subprocess.run("ls -la")`) are never flagged. A candidate is emitted only
when tainted data actually reaches the command argument — direct taint,
assignment, f-string, concatenation, `%` formatting or `.format()`.

### Deliberate safe cases (limitations)

- **List-form (argument vector) invocations are not flagged**: a first
  argument that is a list/tuple literal such as
  `subprocess.run(["ping", "-c", "1", host])` never produces a finding,
  even when it contains tainted values. Rationale: without `shell=True` the
  values are not parsed by a shell. This also misses genuinely dangerous
  forms like `subprocess.run(["bash", "-c", cmd])`.
- **`shlex.quote(...)` acts as a natural sanitizer**: taint does not flow
  through unknown calls, so `subprocess.run("ping " + shlex.quote(host))`
  is not flagged. Good for precision, but it means custom sanitizer wrappers
  are never trusted (same stance as SQL).

### Sanitization

No explicit sanitizer detection (no `is_sanitized` logic): the only safe
cases are constant commands and list-form invocation, both handled at sink
matching time.

### Confidence

Shared scoring (see below): request-origin flow 0.9, poisoned-param flow
0.7, minus 0.1 for chains of >= 3 intermediate steps.

## SSRF

`backend/app/scan/rules/ssrf.py`

### Sources

Identical to the other rules: Flask-style `request` objects (`request.args` /
`form` / `values` / `json` / `cookies` / `headers`) plus poisoned function
parameters, via shared `rules/common.py` logic.

### Sinks

Python HTTP client APIs — kind `http_request`:

| API | URL position |
|---|---|
| `requests.get / post / put / delete / patch / head / options` | first positional |
| `requests.request(method, url)` | second positional |
| `httpx.get / post / put / delete / patch` | first positional |
| `httpx.request(method, url)` | second positional |
| `urllib.request.urlopen(url)` | first positional |

### URL argument handling

The URL is located by the rule's `sink_expression` hook (the shared engine
only taint-checks the expression that hook returns):

1. an explicit `url=` keyword argument wins;
2. otherwise positional: the first argument for regular verbs, the second
   for `*.request(method, url)`.

A finding is emitted **only when that URL expression carries tainted data** —
HTTP requests with constant URLs are never flagged, and neither are
constant-URL variables (`url = "https://example.com/api"; requests.get(url)`).

### Propagation

Everything the shared engine already supports: direct taint, assignments,
f-strings, `+` concatenation, `%` formatting, `.format()`, attribute /
subscript access, collection literals, loop variables, augmented assignment.

### Safe cases (MVP scope)

- constant URL literals and constant-URL variables → ignored
- shell commands (`subprocess`/`os`) are command injection's domain, never SSRF
- no target classification yet: `localhost`, `127.0.0.1`, private IPs and
  cloud metadata endpoints are NOT special-cased. The scanner's job at this
  stage is exactly *user controlled input → HTTP request sink*; the rule is
  structured (`sink_expression` + rule-level hooks) so that a target
  classifier (hostname/IP/metadata heuristics) can be slotted in later
  without touching the engine.

### No network requests, ever

The scanner is a pure AST analysis. It never executes the analyzed code and
never resolves or fetches URLs found in the repository — findings are built
from syntax and static data flow only. (Enforced by tests that monkeypatch
`urllib.request.urlopen` and `socket.socket` to fail.)

### Confidence

Shared scoring: request-origin flow 0.9, poisoned-param flow 0.7, minus 0.1
for chains of >= 3 intermediate steps.

## Confidence calculation

Deterministic, documented, no LLM:

| Condition | Score |
|---|---|
| flow starts from an explicit request object | base 0.9 |
| flow starts from a poisoned function parameter | base 0.7 |
| >= 3 intermediate steps (assignment/propagation/string construction) | −0.1 |

## Current limitations

- **Intra-procedural only**: taint does not cross function call boundaries.
  `x = build_query(user_id)` followed by `cursor.execute(x)` is NOT flagged.
- Field-insensitive: `d["a"] = ...` then `d["a"]` reads are not tracked into
  containers (whole-container taint only).
- No aliasing: `a = b` is tracked via name copy; `a = [b]` only at literal
  level.
- The `FunctionSummary` records observations (params reaching sinks,
  `returns_taint`) but is not yet consumed for inter-procedural resolution.
- Sink recognition is name-based (heuristic); wrapper libraries that call
  `execute` under a different name are missed.
- Command sinks are matched on the exact dotted name: aliased imports
  (`import subprocess as sp`) and `from subprocess import run` are missed.
- Command list-form invocations are never flagged (see command injection
  section); `shlex.quote`-wrapped commands are treated as safe by
  non-propagation through unknown calls.
- HTTP sinks are matched on the exact dotted name (`import requests as r` /
  `from requests import get` are missed); `requests.request` is only
  recognized with the URL as second positional or `url=` keyword.
- SSRF has no target classification (localhost / private IP / metadata
  endpoints are all treated alike) — see the SSRF section.
- Module/class-level control flow is linearized (order-dependent).

## Future cross-function analysis

1. Two-pass approach: analyze callees first, build `FunctionSummary`
   (tainted params, sinks, returns_taint) per function per file.
2. On a call `y = foo(x)` with `x` tainted, consult `foo`'s summary:
   - if `foo`'s summary says the param position reaches a sink, attribute
     the finding to the caller (with the caller's source);
   - if `returns_taint`, mark `y` tainted.
3. Extend summaries across files via the `module_map` in the `CodeModel`,
   then across repositories with a call-graph builder (future CPG).
