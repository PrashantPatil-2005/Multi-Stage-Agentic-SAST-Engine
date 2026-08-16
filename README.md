# Multi-Stage Agentic SAST Engine

Automated source-code security scanner for interpreted languages (Python first),
combining static taint analysis with LLM-assisted validation to reduce false
positives.

## Problem

Pattern-based SAST tools produce high false-positive rates. This engine runs a
seven-stage pipeline where the LLM validates candidate findings against real
code evidence and confirms exploitability before anything is acted upon.

## Pipeline

PREPARE → SCAN → DEDUPLICATE → RISK/SLA → VALIDATE → PROVE → HUMAN APPROVAL

1. PREPARE: parse the repo into a code model (Python AST; CPG later) — no compilation needed
2. SCAN: taint/data-flow analysis → candidate findings (SQLi, command injection, SSRF)
3. DEDUPLICATE: group structurally identical findings across repositories (see `backend/app/dedup/README.md`)
4. RISK/SLA: deterministic risk score + priority, SLA deadlines, breach escalation (see `backend/app/risk/README.md`)
5. VALIDATE: LLM judges each finding against sealed code evidence → verdict + confidence
6. PROVE: safe, sandboxed proof-of-concept evidence for confirmed findings
7. HUMAN APPROVAL: auditable human-in-the-loop permission state before any action (see `backend/app/approval/README.md`)

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

- Findings, risk assessments, validation results, proofs, approvals and
  benchmark reports are stored **in memory per API process**; restarting the
  backend clears them. Data is not persisted to disk and is not shared between
  processes.
- LLM validation requires a live, configured model (see `.env.example`). It is
  deliberately **not** triggered automatically: each finding is validated on
  demand so no hidden cloud calls happen during a demo.
- The proof sandbox must never execute untrusted code on the host; it is
  designed for controlled fixtures only.
- Only three vulnerability rules (SQLi, command injection, SSRF) are implemented.
- Frontend "coming soon" controls (search, repository selector, notifications,
  profile) are placeholders and are disabled.

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

1. Start the backend (`uvicorn app.main:app`) and the frontend (`npm run dev`).
2. Ingest a repository:
   `POST /api/projects` with `{"name":"demo","source_type":"directory","location":"<absolute path to backend/tests/fixtures/vulnerable_python_app>"}`.
3. Run a scan: `POST /api/projects/{id}/scan` — populates findings, risk and SLA.
4. Open the frontend at http://127.0.0.1:5173 and walk the pipeline pages:
   Overview → Findings → Repositories → Risk & SLA → Validation → Proof →
   Approvals → Benchmarks.
5. (Optional) With `LLM_*` configured, `POST /api/findings/{id}/validate`
   produces a real LLM verdict; `POST /api/findings/{id}/prove` then proves a
   `true_positive` finding in the sandbox.

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/projects` | Ingest a repo (directory / zip / git) and build its ProjectSnapshot |
| GET | `/api/projects/{id}` | Project metadata + parsed file summary |
| POST | `/api/projects/{id}/scan` | Run the scanner on a prepared project (populates findings) |
| GET | `/api/findings` | List findings |
| POST | `/api/findings/{id}/validate` | LLM-validate a candidate finding (`LLM_*` env config required) |
| GET | `/api/findings/{id}/validation` | Stored ValidationResult for a finding |
| POST | `/api/findings/{id}/prove` | Sandboxed proof (only for `true_positive` findings) |
| GET | `/api/findings/{id}/proof` | Stored ProofResult for a finding |
| POST | `/api/deduplicate` | Group findings (by id) into structural deduplication groups |
| GET | `/api/deduplication/{fingerprint}` | One deduplication group (by fingerprint) |
| POST | `/api/findings/{id}/risk` | Deterministic risk assessment (uses stored validation/proof) |
| GET | `/api/findings/{id}/risk` | Stored RiskAssessment |
| POST | `/api/findings/{id}/sla` | Create SLA record from stored risk |
| GET | `/api/findings/{id}/sla` | Stored SLARecord |
| POST | `/api/findings/{id}/sla/check` | Evaluate deadline (optional test time `{"now": ...}`) |
| POST | `/api/findings/{id}/sla/resolve` | Mark SLA resolved (optional `{"resolved_at": ...}`) |
| GET | `/api/findings/{id}/escalations` | Escalation event history |
| POST | `/api/findings/{id}/approval` | Create an approval request (requires true_positive + verified proof) |
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