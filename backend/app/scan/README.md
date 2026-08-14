# SCAN stage — taint analysis (SQL injection)

Deterministic, rule-driven static taint analysis over the `CodeModel`
produced by PREPARE. No LLM, no regex-only detection, no code execution:
the engine reasons about **source → propagation → sink** using the Python
AST extracted from each file's actual source.

## Rules

- [SQL injection](#sql-injection) — `backend/app/scan/rules/sql_injection.py`
- [Command injection](#command-injection) — `backend/app/scan/rules/command_injection.py`

Each rule implements the `ScanRule` contract (`is_source`, `match_sink`,
`is_sanitized`, `confidence`, `poison_params`) and is driven by the same
`TaintEngine`. Shared logic (request-object sources, confidence scoring)
lives in `backend/app/scan/rules/common.py`.

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
