# Multi-Stage Agentic SAST Engine

Automated source-code security scanner for interpreted languages (Python first),
combining static taint analysis with LLM-assisted validation to reduce false
positives.

## Problem

Pattern-based SAST tools produce high false-positive rates. This engine runs an
eight-stage pipeline where the LLM validates candidate findings against real
code evidence and confirms exploitability before anything is acted upon.

## Pipeline

PREPARE → SCAN → DEDUPLICATE → RISK → SLA → VALIDATE → PROVE → APPROVAL

1. PREPARE: parse the repo into a code model (Python AST; CPG later) — no compilation needed
2. SCAN: taint/data-flow analysis → candidate findings (SQLi, command injection, SSRF)
3. DEDUPLICATE: group structurally identical findings across repositories (see `backend/app/dedup/README.md`)
4. RISK: deterministic risk score + priority (see `backend/app/risk/README.md`)
5. SLA: deadline per priority, breach escalation (see `backend/app/risk/README.md`)
6. VALIDATE: LLM judges each finding against sealed code evidence → verdict + confidence
7. PROVE: safe, sandboxed proof-of-concept evidence for confirmed findings
8. APPROVAL: auditable human-in-the-loop permission state before any action (see `backend/app/approval/README.md`)

The eight stages are **not automatically chained**: each stage is triggered by
its own explicit user action, and a scan run only records an execution for the
stages that actually ran (see the demo walkthrough below).

Semgrep benchmarking (`backend/app/benchmark/`) is an **optional evaluation
path** that compares our engine against Semgrep on controlled fixtures. It is
NOT part of the production pipeline. Benchmark results are fixture-specific and
are not a claim of real-world accuracy.

## Tech Stack

- Backend: Python + FastAPI, pytest
- Analysis: Python AST (CPG-extensible interface)
- Database: SQLite for local dev / tests (PostgreSQL-ready)
- LLM: provider-agnostic (OpenAI-compatible, env-configured; verified against Hugging Face)
- Frontend: React + TypeScript + Vite
- Tooling: Docker Compose, Semgrep baseline comparison

## Status

- [x] PREPARE: repository ingestion + Python AST parsing + ProjectSnapshot + API
- [x] SCAN: SQL Injection
- [x] SCAN: Command Injection
- [x] SCAN: SSRF (see `backend/app/scan/README.md`)
- [x] Cross-repository finding deduplication (see `backend/app/dedup/README.md`)
- [x] Risk prioritization (see `backend/app/risk/README.md`)
- [x] SLA tracking and escalation (see `backend/app/risk/README.md`)
- [x] VALIDATE: LLM-assisted finding validation (see `backend/app/validate/README.md`)
- [x] PROVE: sandboxed verification (see `backend/app/prove/README.md`)
- [x] Human approval workflow (see `backend/app/approval/README.md`)
- [x] Semgrep benchmark (optional evaluation path; see `backend/app/benchmark/README.md`)
- [x] Dashboard overview (frontend; read-only summary API in `backend/app/api/routes/dashboard.py`)
- [x] Findings list (frontend; read-only API in `backend/app/api/routes/findings.py`)

## Known Limitations

- Pipeline state (projects, findings, risk, SLA, validation, proof, approval,
  benchmark and scan-run records) is persisted to **SQLite** (single process).
  There is no distributed worker setup, no automatic pipeline chaining, no
  per-stage re-runs and no PostgreSQL/Alembic deployment today.
- LLM validation requires a live, configured model (see `.env.example`). It is
  deliberately **not** triggered automatically: each finding is validated on
  demand so no hidden cloud calls happen during a demo.
- The proof sandbox must never execute untrusted code on the host; it is
  designed for controlled fixtures only.
- Only three vulnerability rules (SQLi, command injection, SSRF) are implemented.
- Frontend "coming soon" controls (global search, repository selector,
  notifications, profile menu) are placeholders and are disabled; the
  per-page filters and search that exist are functional.
- Authentication is not implemented. Approval decisions are recorded under a
  static demo reviewer identity (`security-analyst`); it is not a verified
  human account.

## Running the backend

Requirements: Python >= 3.11, git (for git-source ingestion).

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Windows; `source .venv/bin/activate` on Linux/macOS
pip install -e ".[dev]"
uvicorn app.main:app --reload         # http://127.0.0.1:8000
```

Configuration is via environment variables / `.env` (see `.env.example`, prefix `SAST_`).
No secrets are hardcoded and none are committed.

## Running the frontend

Requirements: Node.js + npm.

```powershell
cd frontend
npm install
npm run dev                           # http://127.0.0.1:5173 (proxies /api to :8000)
```

Production build: `npm run build` (outputs to `frontend/dist/`).

## LLM configuration and smoke test

LLM validation reads `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`
and `LLM_TIMEOUT_SECONDS` from the environment or `backend/.env` (see
`backend/.env.example`). The default provider is Hugging Face
(`https://router.huggingface.co/v1`), OpenAI-compatible.

A standalone smoke test verifies the configured model end to end without
starting the server (it never prints the API key):

```powershell
cd backend
.\.venv\Scripts\python.exe .\smoke_validate_hf.py
```

## Demo walkthrough

The complete user journey, driven entirely from the UI (start the backend
`uvicorn app.main:app` and the frontend `npm run dev`, then open
http://127.0.0.1:5173):

1. **Add a repository** — Repositories → Add Repository (Git URL, or use a
   directory/zip via the API examples below). PREPARE runs when the repository
   is added.
2. **Confirm PREPARE** — the confirmation shows the real prepare summary
   (file count, Python files, parse failures) and the row shows the `prepared`
   status.
3. **Scan** — click Scan on the repository row (synchronous; returns the scan
   run).
4. **Open Scan History** — the repository's Scan History lists the new scan
   run (newest first).
5. **Open the Scan Run** — click "View run" to see run details and the
   per-stage status board (SCAN completed; the other stages `pending` until
   they run).
6. **Open Findings** — "View Findings" on a repository opens the
   repository-scoped finding list.
7. **Open Finding Detail** — open any finding to see its owning repository +
   producing scan runs (lineage), taint path and evidence.
8. **Select Scan Run (if necessary)** — a finding produced by several runs
   shows a run-context selector; pick one before acting. A single producing
   run is used automatically. No action ever guesses a "latest" run.
9. **Deduplicate** — Deduplicate on the repository row groups structurally
   identical findings (choose the run context when prompted).
10. **Assess Risk** — finding → Risk panel "Assess Risk".
11. **Start SLA** — finding → SLA panel "Start SLA" (deadline per priority).
12. **Check SLA** — finding → SLA panel "Check SLA" to walk the deadline
    state machine.
13. **Validate** — finding → Validation panel "Validate" (requires `LLM_*`
    config, see below; the button is hidden without configuration and the API
    returns 503).
14. **Prove** — after a `true_positive` verdict, finding → Proof panel
    "Prove Finding"; the result shows a safe summary.
15. **Request Approval** — an eligible (validated `true_positive` + proven
    `verified`) finding → Human Approval panel "Request Approval".
16. **Approve** — Approvals page (or the finding's Human Approval panel)
    records the decision under the demo reviewer identity and appends to the
    audit trail; open "History" to review events.
17. **Return to the Scan Run** — open the same run from Scan History again.
18. **Verify execution history** — the run shows all eight stages
    (PREPARE, SCAN, DEDUPLICATE, RISK, SLA, VALIDATE, PROVE, APPROVAL) with
    the status, execution count and append-only history of each.

Notes on this demo:

- Approval decisions are recorded under the static demo reviewer identity
  `security-analyst`. **Authentication is not implemented** — the reviewer is
  a demo label, not a verified human account.
- **Stages are triggered manually.** Each step above is its own explicit
  action; there is **no automatic full-pipeline execution** — a scan never
  auto-deduplicates, risk never auto-starts an SLA, and so on. The Scan Run
  page shows `pending` until a stage is explicitly executed, `completed` when
  its latest explicit execution succeeded, `failed` when it failed.
- For a quick reproducible run you can ingest the bundled fixture repository
  via the API (a directory source — see the examples below). The fixture at
  `backend/tests/fixtures/vulnerable_python_app/` contains intentional SQLi,
  command-injection and SSRF patterns and produces real findings.
- **Benchmarks (optional)** — Benchmarks page runs our engine vs Semgrep on
  a controlled fixture (offline; `semgrep` on PATH is optional).

The API examples below are equivalent ways to drive the same flow (e.g. to
ingest a local directory or zip archive that the UI's Git-first form does not
cover).

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/projects` | Ingest a repo (directory / zip / git) and build its ProjectSnapshot (PREPARE) |
| GET | `/api/projects/{id}` | Project metadata + parsed file summary |
| DELETE | `/api/projects/{id}` | Delete a repository and everything it owns (scan runs, findings, risk/SLA, validation, proof, approval, dedup membership, prepared snapshot) |
| GET | `/api/repositories` | Read-only repository summaries (status, findings/risk/validation/proof/SLA aggregates) |
| POST | `/api/projects/{id}/scan` | Run the scanner on a prepared project (synchronous; populates findings; returns `scan_run_id`) |
| GET | `/api/projects/{id}/scans` | Scan history for a project (newest first; status, counts, timestamps) |
| GET | `/api/scans` | Recent scan runs across projects (newest first; read-only) |
| GET | `/api/scans/{scan_run_id}` | Scan run detail including per-stage status and append-only stage execution history |
| GET | `/api/scans/{scan_run_id}/findings` | Findings produced by a scan run (explicit lineage) |
| GET | `/api/findings` | List findings (optional `?project_id=` scopes to one repository via explicit scan lineage) |
| POST | `/api/findings/{id}/validate` | LLM-validate a candidate finding (`LLM_*` env config required; optional `{"scan_run_id": ...}` records the VALIDATE stage execution) |
| GET | `/api/findings/{id}/validation` | Stored ValidationResult for a finding |
| POST | `/api/findings/{id}/prove` | Sandboxed proof (only for `true_positive` findings; optional `{"scan_run_id": ...}` records the PROVE stage execution) |
| GET | `/api/findings/{id}/proof` | Stored ProofResult for a finding |
| POST | `/api/deduplicate` | Group findings (by id) into structural deduplication groups (optional `{"scan_run_id": ...}` records the DEDUPLICATE stage execution) |
| GET | `/api/deduplication/{fingerprint}` | One deduplication group (by fingerprint) |
| POST | `/api/findings/{id}/risk` | Deterministic risk assessment (uses stored validation/proof; optional `{"scan_run_id": ...}` records the RISK stage execution) |
| GET | `/api/findings/{id}/risk` | Stored RiskAssessment |
| POST | `/api/findings/{id}/sla` | Create SLA record from stored risk (optional `{"scan_run_id": ...}` records the SLA stage execution) |
| GET | `/api/findings/{id}/sla` | Stored SLARecord |
| POST | `/api/findings/{id}/sla/check` | Evaluate deadline (optional test time `{"now": ...}`, optional `{"scan_run_id": ...}` records the SLA stage execution) |
| POST | `/api/findings/{id}/sla/resolve` | Mark SLA resolved (optional `{"resolved_at": ...}`) |
| GET | `/api/findings/{id}/escalations` | Escalation event history |
| POST | `/api/findings/{id}/approval` | Create an approval request (requires true_positive + verified proof; optional `{"scan_run_id": ...}` records the APPROVAL stage execution; decisions inherit the request's run) |
| GET | `/api/findings/{id}/approval` | Latest approval request for a finding |
| POST | `/api/approvals/{id}/approve` | Approve (terminal, audits reviewer + reason) |
| POST | `/api/approvals/{id}/reject` | Reject (terminal) |
| POST | `/api/approvals/{id}/request-changes` | Send back for changes |
| POST | `/api/approvals/{id}/resubmit` | changes_requested → pending (version + 1) |
| GET | `/api/approvals/{id}/history` | Append-only audit event trail |
| GET | `/api/benchmarks` | List benchmark reports |
| POST | `/api/benchmarks/semgrep` | Run our engine vs Semgrep on a controlled fixture (offline; `semgrep` optional) |
| GET | `/api/benchmarks/{benchmark_id}` | Stored benchmark report |
| GET | `/api/health` | Health check |

Examples:

```powershell
# from a local directory
$body = '{"name":"vuln-app","source_type":"directory","location":"C:/Users/Prash/Desktop/SAST/backend/tests/fixtures/vulnerable_python_app"}'
$resp = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/projects -ContentType "application/json" -Body $body
$resp.id

# run a scan on the prepared project
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/projects/$($resp.id)/scan"

# from a zip archive
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/projects `
  -ContentType "application/json" `
  -Body '{"name":"vuln-app","source_type":"zip","location":"C:/path/to/repo.zip"}'

# from a git URL (requires git on PATH; shallow clone)
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/projects `
  -ContentType "application/json" `
  -Body '{"name":"demo","source_type":"git","location":"https://github.com/org/repo.git"}'

# fetch the prepared project (files, hashes, function/class/import/call counts)
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8000/api/projects/$($resp.id)"
```

## Running the tests

```powershell
cd backend
.\.venv\Scripts\python -m pytest      # full backend suite (offline; no LLM required)
```

```powershell
cd frontend
npx vitest run                         # full frontend suite
```

The fixture repository `backend/tests/fixtures/vulnerable_python_app/` contains
intentionally vulnerable patterns (SQLi, command injection, SSRF) for SCAN-stage
testing, plus poison/syntax-error/ignored-dir files to prove the engine never
executes target code and only ingests relevant files.

## What PREPARE produces

`POST /api/projects` stores, per project, in `workspace/projects/{id}/`:

- `repo/` — a private copy of the ingested repository (ignored dirs removed)
- `snapshot.json` — the `ProjectSnapshot`: per-file path/source/SHA-256/AST/
  functions/classes/imports/calls/assignments/line numbers, plus summary
- `codemodel.json` — the analysis-ready `CodeModel` built via `ICodeModelBuilder`

Security properties: nothing from the target repo is imported or executed;
ZIP path traversal/symlink/encrypted entries are rejected; extraction is confined to
the workspace; per-file and aggregate size limits apply; `.git`, `node_modules`,
`__pycache__`, venvs and similar directories are ignored. Git clone error output
is redacted (credentials never leak into API responses).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).