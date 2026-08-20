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

1. PREPARE: parse the repo into a code model (Python AST + CPG; AST + CFG + DFG) — no compilation needed
2. SCAN: taint/data-flow analysis → candidate findings (SQLi, command injection, SSRF, deserialization)
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
- Analysis: Python AST + Code Property Graph (CPG; AST + CFG + DFG)
- Database: SQLite via SQLAlchemy for local dev / tests (PostgreSQL-ready)
- Auth: bcrypt password hashing, server-side sessions (HttpOnly cookies), RBAC (4 roles)
- LLM: provider-agnostic (OpenAI-compatible, env-configured; verified against Hugging Face)
- Frontend: React 18 + TypeScript + Vite, React Router 6
- Integrations: DefectDojo (external ticketing), Semgrep (optional benchmark)
- Deployment: Render.com (see `render.yaml`)

## Status

- [x] PREPARE: repository ingestion + Python AST parsing + ProjectSnapshot + API
- [x] PREPARE: Code Property Graph (CPG) builder (AST + CFG + DFG; see `backend/app/prepare/cpg/`)
- [x] SCAN: SQL Injection
- [x] SCAN: Command Injection
- [x] SCAN: SSRF (see `backend/app/scan/README.md`)
- [x] SCAN: Deserialization (pickle, yaml.load, marshal, shelve, jsonpickle)
- [x] Cross-repository finding deduplication (see `backend/app/dedup/README.md`)
- [x] Risk prioritization (see `backend/app/risk/README.md`)
- [x] SLA tracking and escalation (see `backend/app/risk/README.md`)
- [x] VALIDATE: LLM-assisted finding validation (see `backend/app/validate/README.md`)
- [x] PROVE: sandboxed verification (see `backend/app/prove/README.md`)
- [x] Human approval workflow (see `backend/app/approval/README.md`)
- [x] Remediation workflow (propose → apply → verify; see `backend/app/remediation/`)
- [x] Authentication & RBAC (bcrypt + server-side sessions; 4 roles, ~30 permissions)
- [x] DefectDojo integration (external ticketing for remediation tracking)
- [x] Notifications system
- [x] Semgrep benchmark (optional evaluation path; see `backend/app/benchmark/README.md`)
- [x] Full frontend: Dashboard, Findings, Repositories, Risk, Validation, Proof, Approvals, Benchmark, DefectDojo, Settings, Profile, Login

## Known Limitations

- Pipeline state (projects, findings, risk, SLA, validation, proof, approval,
  remediation, benchmark and scan-run records) is persisted to **SQLite** (single process).
  There is no distributed worker setup, no automatic pipeline chaining, no
  per-stage re-runs and no PostgreSQL/Alembic deployment today.
- LLM validation requires a live, configured model (see `.env.example`). It is
  deliberately **not** triggered automatically: each finding is validated on
  demand so no hidden cloud calls happen during a demo.
- The proof sandbox must never execute untrusted code on the host; it is
  designed for controlled fixtures only.
- Four vulnerability rules are implemented: SQL injection, command injection,
  SSRF, and deserialization. Additional rules require new taint-source/sink pairs.
- Only Python repositories are supported for ingestion (CPG-extensible interface
  exists for future languages).
- DefectDojo integration requires a running DefectDojo instance with API access.
- Authentication uses server-side sessions (no JWT/token-based API auth yet).

## Authentication & Authorization

The platform uses bcrypt password hashing with server-side sessions stored in
SQLite. Sessions are managed via HttpOnly cookies. Role-based access control
(RBAC) enforces permissions per endpoint.

**Roles:** `analyst`, `manager`, `developer`, `auditor`

| Role | Capabilities |
|---|---|
| analyst | View all + scan, deduplicate, validate, prove, assess risk, manage SLA, request approval, run benchmarks |
| manager | All analyst permissions + approve/reject/resubmit, propose/apply/verify remediation, delete repositories |
| developer | View all + propose/apply/verify remediation, scan, create repositories |
| auditor | Read-only access to all resources |

Demo users are seeded automatically on first startup. See `backend/app/auth/seed.py`.

## Remediation Workflow

After a finding is approved, developers can propose, apply, and verify remediation
patches. Patches are deterministic line-anchored edits generated from the finding's
code evidence. The workflow:

1. **Propose** — generates a remediation patch from the finding's code evidence
2. **Apply** — writes the patch to the repository's workspace copy
3. **Verify** — re-scans the patched code to confirm the vulnerability is resolved

See `backend/app/remediation/` for details.

## DefectDojo Integration

The platform can create external tickets in DefectDojo for findings that require
tracking outside the system. Requires a running DefectDojo instance with API access
configured via `SAST_DEFECTDOJO_*` environment variables.

See `backend/app/defectdojo/` for details.

## Deployment

The project includes a Render.com deployment configuration (`render.yaml`) that
builds the frontend, installs the backend, and runs `start.sh` (which launches
`python -m uvicorn app.main:app`). In production, the FastAPI app serves the
built frontend from `frontend/dist/`.

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
npm run dev                           # http://127.0.0.1:5173 (proxies /api to :8080)
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

1. **Log in** — use the Login page (demo users are seeded automatically:
   `admin`/`admin` for manager role, `analyst`/`analyst` for analyst role).
2. **Add a repository** — Repositories → Add Repository (Git URL, or use a
   directory/zip via the API examples below). PREPARE runs when the repository
   is added.
3. **Confirm PREPARE** — the confirmation shows the real prepare summary
   (file count, Python files, parse failures) and the row shows the `prepared`
   status.
4. **Scan** — click Scan on the repository row (synchronous; returns the scan
   run).
5. **Open Scan History** — the repository's Scan History lists the new scan
   run (newest first).
6. **Open the Scan Run** — click "View run" to see run details and the
   per-stage status board (SCAN completed; the other stages `pending` until
   they run).
7. **Open Findings** — "View Findings" on a repository opens the
   repository-scoped finding list.
8. **Open Finding Detail** — open any finding to see its owning repository +
   producing scan runs (lineage), taint path and evidence.
9. **Select Scan Run (if necessary)** — a finding produced by several runs
   shows a run-context selector; pick one before acting. A single producing
   run is used automatically. No action ever guesses a "latest" run.
10. **Deduplicate** — Deduplicate on the repository row groups structurally
    identical findings (choose the run context when prompted).
11. **Assess Risk** — finding → Risk panel "Assess Risk".
12. **Start SLA** — finding → SLA panel "Start SLA" (deadline per priority).
13. **Check SLA** — finding → SLA panel "Check SLA" to walk the deadline
    state machine.
14. **Validate** — finding → Validation panel "Validate" (requires `LLM_*`
    config, see below; the button is hidden without configuration and the API
    returns 503).
15. **Prove** — after a `true_positive` verdict, finding → Proof panel
    "Prove Finding"; the result shows a safe summary.
16. **Request Approval** — an eligible (validated `true_positive` + proven
    `verified`) finding → Human Approval panel "Request Approval".
17. **Approve** — Approvals page (or the finding's Human Approval panel)
    records the decision under the authenticated user's identity and appends
    to the audit trail; open "History" to review events.
18. **Remediate** — after approval, finding → Remediation panel "Propose
    Remediation" to generate a patch, then "Apply" to write it, and "Verify"
    to confirm the fix.
19. **Return to the Scan Run** — open the same run from Scan History again.
20. **Verify execution history** — the run shows all eight stages
    (PREPARE, SCAN, DEDUPLICATE, RISK, SLA, VALIDATE, PROVE, APPROVAL) with
    the status, execution count and append-only history of each.

Notes on this demo:

- **Authentication is required.** The UI redirects to the Login page when
  no session cookie is present. Approval and remediation decisions are
  recorded under the authenticated user's identity.
- **Stages are triggered manually.** Each step above is its own explicit
  action; there is **no automatic full-pipeline execution** — a scan never
  auto-deduplicates, risk never auto-starts an SLA, and so on. The Scan Run
  page shows `pending` until a stage is explicitly executed, `completed` when
  its latest explicit execution succeeded, `failed` when it failed.
- For a quick reproducible run you can ingest the bundled fixture repository
  via the API (a directory source — see the examples below). The fixture at
  `backend/tests/fixtures/vulnerable_python_app/` contains intentional SQLi,
  command-injection, SSRF, and deserialization patterns and produces real findings.
- **Benchmarks (optional)** — Benchmarks page runs our engine vs Semgrep on
  a controlled fixture (offline; `semgrep` on PATH is optional).
- **DefectDojo (optional)** — DefectDojo page creates external tickets for
  findings requiring a running DefectDojo instance with API access.

The API examples below are equivalent ways to drive the same flow (e.g. to
ingest a local directory or zip archive that the UI's Git-first form does not
cover).

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/projects` | Ingest a repo (directory / zip / git) and build its ProjectSnapshot (PREPARE) |
| GET | `/api/projects/{id}` | Project metadata + parsed file summary |
| DELETE | `/api/projects/{id}` | Delete a repository and everything it owns (scan runs, findings, risk/SLA, validation, proof, approval, remediation, dedup membership, prepared snapshot) |
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
| POST | `/api/findings/{id}/remediation/propose` | Propose a remediation patch for a verified finding |
| POST | `/api/findings/{id}/remediation/apply` | Apply the proposed remediation patch |
| POST | `/api/findings/{id}/remediation/verify` | Verify the applied remediation |
| GET | `/api/proof-summary` | Aggregate proof metrics across findings |
| GET | `/api/risk-summary` | Aggregate risk and SLA metrics across findings |
| GET | `/api/validation-summary` | Aggregate validation metrics across findings |
| GET | `/api/notifications` | List notifications for the current user |
| PUT | `/api/notifications/{id}/read` | Mark a notification as read |
| POST | `/api/defectdojo/tickets` | Create a DefectDojo ticket for a finding |
| GET | `/api/defectdojo/status` | Check DefectDojo integration status |
| POST | `/api/auth/login` | Log in (username + password; sets session cookie) |
| POST | `/api/auth/logout` | Log out (destroys session) |
| GET | `/api/auth/me` | Current authenticated user profile |
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
intentionally vulnerable patterns (SQLi, command injection, SSRF, deserialization)
for SCAN-stage testing, plus poison/syntax-error/ignored-dir files to prove the
engine never executes target code and only ingests relevant files.

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