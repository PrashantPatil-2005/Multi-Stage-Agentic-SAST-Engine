# Multi-Stage Agentic SAST Engine

Automated source-code security scanner for interpreted languages (Python first),
combining static taint analysis with LLM-assisted validation to reduce false positives.

## Problem

Pattern-based SAST tools produce high false-positive rates. This engine runs a
four-stage pipeline where the LLM validates candidate findings against real code
evidence and confirms exploitability before anything is acted upon.

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
NOT part of the production pipeline.

## Tech Stack (planned)

- Backend: Python + FastAPI, pytest
- Analysis: Python AST (CPG-extensible interface)
- Database: PostgreSQL (SQLite for local dev / tests)
- LLM: provider-agnostic (OpenAI-compatible, env-configured)
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
- [ ] Dashboard

## Running the PREPARE stage (backend)

Requirements: Python >= 3.11, git (for git-source ingestion).

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Windows; `source .venv/bin/activate` on Linux/macOS
pip install -e ".[dev]"
uvicorn app.main:app --reload         # http://127.0.0.1:8000
```

Configuration is via environment variables / `.env` (see `.env.example`, prefix `SAST_`).
No secrets are hardcoded.

### API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/projects` | Ingest a repo (directory / zip / git) and build its ProjectSnapshot |
| GET | `/api/projects/{id}` | Project metadata + parsed file summary |
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
| POST | `/api/benchmarks/semgrep` | Benchmark our engine vs Semgrep on a controlled fixture (offline; `semgrep` optional) |
| GET | `/api/benchmarks/{benchmark_id}` | Stored benchmark report |
| GET | `/api/health` | Health check |

Examples:

```powershell
# from a local directory
$body = '{"name":"vuln-app","source_type":"directory","location":"C:/Users/Prash/Desktop/SAST/backend/tests/fixtures/vulnerable_python_app"}'
$resp = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/projects -ContentType "application/json" -Body $body
$resp.id

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

### Running the tests

```powershell
cd backend
.\.venv\Scripts\python -m pytest        # 340 tests: PREPARE, SCAN (3 rules), DEDUP, RISK/SLA, VALIDATE, PROVE, APPROVAL, BENCHMARK, API
```

The fixture repository `backend/tests/fixtures/vulnerable_python_app/` contains
intentionally vulnerable patterns (SQLi, command injection, SSRF) for later SCAN-stage
testing, plus poison/syntax-error/ignored-dir files to prove the engine never executes
target code and only ingests relevant files.

### What PREPARE produces

`POST /api/projects` stores, per project, in `workspace/projects/{id}/`:

- `repo/` — a private copy of the ingested repository (ignored dirs removed)
- `snapshot.json` — the `ProjectSnapshot`: per-file path/source/SHA-256/AST/
  functions/classes/imports/calls/assignments/line numbers, plus summary
- `codemodel.json` — the analysis-ready `CodeModel` built via `ICodeModelBuilder`

Security properties: nothing from the target repo is imported or executed;
ZIP path traversal/symlink/encrypted entries are rejected; extraction is confined to
the workspace; per-file and aggregate size limits apply; `.git`, `node_modules`,
`__pycache__`, venvs and similar directories are ignored.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md).