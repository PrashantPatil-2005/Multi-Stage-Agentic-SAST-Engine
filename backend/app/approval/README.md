# Human Approval Workflow (HUMAN APPROVAL)

Explicit human-in-the-loop **permission state** for findings that passed the
VALIDATE gate (`true_positive`) and the PROVE gate (`verified`). An approval
**never executes anything** — it only records permission + an audit trail, so
a future remediation/action engine can check `is_action_allowed(...)` before
touching a repository.

## State machine

```
pending ──┬─→ approved            (terminal)
          ├─→ rejected            (terminal)
          └─→ changes_requested
changes_requested ──→ pending     (new review cycle; version + 1)
```

Transitions only move forward; `approved`/`rejected` are terminal. Every
transition appends an immutable `ApprovalEvent` (who, when, from → to, why).

## Eligibility gates (default policy)

A request can only be created when:

| Gate | Requirement |
| --- | --- |
| VALIDATE | verdict `true_positive` |
| PROVE | status `verified` |

Gate failures raise `ApprovalGateError` (HTTP 409). Both gates can be
relaxed via `ApprovalPolicy(require_validation=..., require_proof=...)`.

## Policy (`ApprovalPolicy`)

- `require_validation` (default True) — require the VALIDATE gate.
- `require_proof` (default True) — require the PROVE gate.
- `allowed_actions` (default `("remediation",)`) — actions authorized by an
  approved request.
- `allow_re_request_after_terminal` (default False) — allow a fresh request
  after `approved`/`rejected`.

## Semantics

- **Idempotent**: an active request (pending/changes_requested) for the same
  finding + action is returned instead of duplicated.
- **Versioning**: starts at 1; each `changes_requested → pending` cycle bumps
  it (a new review cycle).
- **Action authorization**: `is_action_allowed(approval_id)` is True only
  when status == `approved` and the requested action ∈ `allowed_actions`.
- **Timestamps**: timezone-aware UTC only; naive datetimes are rejected.
- **Audit**: `get_history(approval_id)` returns the append-only event trail
  (creation + every transition).

## API routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/findings/{finding_id}/approval` | create request (body `{action, requested_by}`; body optional) |
| GET | `/api/findings/{finding_id}/approval` | latest request for a finding |
| POST | `/api/approvals/{approval_id}/approve` | approve (terminal) |
| POST | `/api/approvals/{approval_id}/reject` | reject (terminal) |
| POST | `/api/approvals/{approval_id}/request-changes` | send back for changes |
| POST | `/api/approvals/{approval_id}/resubmit` | changes_requested → pending (version + 1) |
| GET | `/api/approvals/{approval_id}/history` | audit event trail |

Errors: `404` (missing finding/approval), `409` (gate failure or invalid
transition), `422` (invalid body / naive datetime).

## Security boundaries

- `approve()`/`reject()`/`request_changes()`/`resubmit()` only mutate
  in-memory state + append audit events — **no** subprocess, shell, file
  modification, network, or LLM calls (covered by dedicated tests).
- Approval state is in-memory (same convention as the other stages); a
  persistence backend can be added later without changing the contracts.

## Integration with other stages

- Reads VALIDATE verdicts from the validation store and PROVE statuses from
  the proof store (the eligibility gate).
- A future remediation engine must call `is_action_allowed(approval_id)`
  before acting; remediation itself is out of scope here.