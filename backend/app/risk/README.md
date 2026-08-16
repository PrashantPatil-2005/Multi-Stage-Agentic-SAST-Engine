# Risk Prioritization + SLA Tracking + Escalation

Stage: **RISK/SLA** — runs after DEDUPLICATION, around VALIDATE/PROVE.

```
DeduplicationGroup
      ↓
canonical finding
      ↓
RiskAssessment      (deterministic, no LLM)
      ↓
SLARecord          (deadline per priority)
      ↓
EscalationEvent    (SLA breach → level 1, idempotent)
```

## Risk formula

```
risk_score = severity_weight[severity]
           + validated_bonus    (+10, verdict == true_positive)
           + proof_bonus        (+10, proof.status == verified,
                                 only when the policy says proof increases
                                 priority)
false_positive  -> risk_score = 0, priority = P4
uncertain       -> base only (unconfirmed, no bonus)
final           -> clamp(risk_score, 0, 100)
```

Factors that are not known are never scored: an unvalidated finding gets no
validation factor, an unproven finding gets no proof factor, and an unknown
severity is weighted 0 with an explanatory factor. Nothing is invented.

### Severity weights (configurable)

| severity | weight |
|---|---|
| critical | 100 |
| high | 75 |
| medium | 50 |
| low | 25 |
| info | 5 |
| unknown | 0 (with explanatory factor) |

The scanner's own severity values are unchanged (SQLi/CMDi/SSRF = HIGH).

### Priority thresholds (configurable)

| score | priority |
|---|---|
| 90–100 | P0 |
| 75–89 | P1 |
| 50–74 | P2 |
| 25–49 | P3 |
| 0–24 | P4 |

Example outcomes: HIGH unvalidated = 75/P1; HIGH validated true_positive =
85/P1; HIGH validated + proven = 95/P0 (default policy); false_positive = 0/P4.

## SLA policy (configurable)

| priority | deadline |
|---|---|
| P0 | 4 hours |
| P1 | 24 hours |
| P2 | 3 days |
| P3 | 7 days |
| P4 | no SLA (`not_applicable`) |

Timestamps are **timezone-aware UTC**; naive datetimes raise `ValueError`
(422 on the API). Transitions only move forward:

```
not_applicable → active → breached → resolved   (resolved is terminal)
```

- `now < due_at` → `active`
- `now >= due_at` → `breached`; `breached_at` is set exactly once
- a resolved SLA is never reactivated; `resolved_at` is recorded once

## Escalation rules

Initial level 0. The first active → breached transition emits exactly one
`EscalationEvent` (previous 0 → new 1) with an explainable reason; repeated
checks on an already-breached record emit nothing. No external notifications
(email/Slack/Telegram) — only structured events, by design.

## Dedup integration

One `DeduplicationGroup` → one risk assessment for its **canonical finding**
(via `RiskService.assess_group`). All member finding ids are preserved on
`related_finding_ids` for traceability, so N identical findings never spawn
N independent SLA records.

## API

| method | path | notes |
|---|---|---|
| POST | `/api/findings/{id}/risk` | assess (uses stored validation/proof) |
| GET | `/api/findings/{id}/risk` | stored assessment |
| POST | `/api/findings/{id}/sla` | create SLA (idempotent per priority) |
| GET | `/api/findings/{id}/sla` | stored record |
| POST | `/api/findings/{id}/sla/check` | body `{"now": iso}` for test time |
| POST | `/api/findings/{id}/sla/resolve` | body `{"resolved_at": iso}` |
| GET | `/api/findings/{id}/escalations` | event history |

Errors: 404 (missing finding/risk/sla), 422 (naive datetime).

## Background evaluation (automatic breach detection)

SLA records are checked on demand via `POST /api/findings/{id}/sla/check` and
**automatically** by `app/risk/sla_evaluator.py` (`SlaEvaluator`), which runs
a small background cycle for the application's lifetime:

- the cycle calls `SlaEvaluator.evaluate_once(now=...)` on a timer
  (`sla_check_interval_seconds`, default 60s, `SAST_SLA_CHECK_INTERVAL_SECONDS`);
- it reuses the exact same `SLAService.check_sla` logic as the manual
  endpoint — the two paths always agree and never double-escalate;
- non-active records (breached / resolved / `not_applicable`) are skipped;
- a failing record is logged and skipped, it never aborts the cycle;
- `evaluate_once` is fully synchronous with an injectable clock, so the
  behavior is directly testable without sleeps;
- single-process assumption: one evaluator instance per application process
  (no distributed locking; appropriate for the current SQLite architecture).

## Idempotency

Risk assessment, SLA check, SLA resolution and escalation generation are
safe to call repeatedly: scores/priorities are deterministic, `breached_at`
and `resolved_at` are set once, and escalation events are never duplicated
— including when the background evaluator and the manual check observe the
same record.

## Limitations

- Severity/priority is derived from static analysis + validation/proof
  state; no asset-criticality or real-world exposure data exists, so those
  factors are intentionally absent.
- Escalation stops at level 1 (SLA breach); higher levels and external
  notification channels are future work.