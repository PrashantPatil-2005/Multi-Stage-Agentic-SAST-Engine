# VALIDATE stage — LLM-assisted finding validation

Takes a `CandidateFinding` from SCAN and produces a `ValidationResult` with
one of three verdicts:

| Verdict | Meaning | Recommended next step |
|---|---|---|
| `true_positive` | attacker-controlled data reaches the sink | `prove` |
| `false_positive` | a safe construction neutralizes the flow | `discard` |
| `uncertain` | static evidence is insufficient to decide | `manual_review` |

The LLM reasons **only** from the supplied static evidence. It never
executes code, never makes network requests, and never invents source,
execution results, or PoCs.

## Architecture

```
CandidateFinding
     | EvidenceBuilder (redacts + trims to the finding's own code)
     v
ValidationEvidence
     | ValidationRequest
     v
LLMProvider.validate            (prompt -> completion -> Pydantic parse
     |                           -> repair once -> UNCERTAIN fallback)
     v
ValidationResult  (stored separately; the CandidateFinding is never mutated)
```

- `models.py` — `ValidationRequest`, `ValidationResult`, `ValidationEvidence`,
  `ValidationMetadata` (Pydantic contracts).
- `evidence.py` — `EvidenceBuilder`: deterministic, redacted, minimal
  evidence package per finding.
- `prompts.py` — grounded system prompt, strict JSON output contract, repair
  prompt.
- `providers/` — `LLMProvider` abstraction + `OpenAICompatibleProvider`.
- `service.py` — `ValidationService.validate(finding)` and
  `validate_report(scan_report)` (sequential batch).
- `store.py` — `FindingStore` / `ValidationStore` used by the API (in-memory
  registry with optional SQLite backing, same convention as the other
  pipeline stores).

## Evidence package

`ValidationEvidence` contains ONLY:

- vulnerability type, severity, scanner confidence
- source location + snippet, sink location + snippet
- taint path (source → propagation → sink), relevant lines
- sanitizer observations
- a small surrounding-context window (±3 lines around source and sink) when
  the file source is available
- repository-relative file paths

The whole repository is never sent. Files and lines outside the finding's
own region are excluded. The exact package used for a validation is stored
on the result (`result.evidence`) and its canonical hash on the metadata.

## LLM provider interface

```python
class LLMProvider(ABC):
    provider_name: str
    model: str | None
    def _complete(self, prompt: str) -> str: ...
    def validate(self, request: ValidationRequest) -> ValidationResult: ...
```

`validate` is a template method shared by all backends: build prompt →
complete → parse with Pydantic → if unusable, retry once with the repair
prompt → if still unusable, return an `uncertain` result. **Malformed model
output is never silently trusted.**

`OpenAICompatibleProvider` POSTs an OpenAI-style chat-completions request
(`temperature: 0`, `response_format: json_object`) to `LLM_BASE_URL`. It is
built exclusively from environment variables — nothing is hardcoded:

| Variable | Meaning |
|---|---|
| `LLM_PROVIDER` | provider id (default `openai_compatible`) |
| `LLM_BASE_URL` | endpoint, e.g. `https://api.openai.com/v1` |
| `LLM_API_KEY` | bearer token |
| `LLM_MODEL` | model id (optional) |

If no configuration exists, `get_provider()` / validation raises
`ConfigurationError` with a clear message; the API returns 503. **The rest
of the scanner is fully usable without an LLM.**

## Prompt grounding (anti-hallucination)

The system prompt mandates:

- every claim must be traceable to the supplied evidence package;
- insufficient evidence → `uncertain`;
- never invent missing code;
- never assume a sanitizer exists unless it is shown;
- never claim runtime behavior that wasn't statically demonstrated;
- never claim a request was actually executed;
- prefer `uncertain` over unsupported `true_positive`.

## Confidence handling

Scanner confidence and LLM confidence are separate values. The model's
confidence must land in `[0, 1]` (Pydantic `Field(ge=0, le=1)`); out-of-range
values are treated like malformed output (repair → `uncertain`). An
`uncertain` verdict is never treated as a confirmed vulnerability, even when
scanner confidence was high.

## Secret redaction

Before anything leaves the process, `redact_secrets` replaces
credential-looking substrings (API keys, passwords, bearer tokens, private
key blocks, database URLs with credentials, AWS/GitHub/Slack tokens) with
`<REDACTED:secret>`. This is a **conservative pattern filter, not a complete
secret scanner** — audit high-value repositories separately.

## Failure behavior

- LLM not configured → `ConfigurationError` → 503 (scanner unaffected).
- Malformed model output → one repair retry → `uncertain` fallback.
- Network/provider errors propagate as `ConfigurationError`-style failures
  from the provider; they never corrupt the candidate finding.

## Observability

`ValidationService` logs: finding id, vulnerability type, provider, model,
duration, verdict. It never logs API keys, repository source, secrets, or
full prompts.

## API

```
POST /api/findings/{finding_id}/validate   body: {"provider": "openai_compatible"}
GET  /api/findings/{finding_id}/validation
```

Findings are registered in the `FindingStore` (e.g.
`get_finding_store().add_report(report)` after a SCAN run); validation
results are recorded in `ValidationStore`, kept separate from findings.
Both stores persist to SQLite when a session factory is configured
(see `app/db/persistence.py`), so findings and validation results survive a
backend restart.

## Limitations

- Verdict quality depends on the model and on the surrounding-context
  window; the scanner does not yet supply cross-function callee summaries
  as evidence.
- Redaction is pattern-based and imperfect.
- Batch validation is sequential (deliberate, for reliability/debugging).
- Providers are synchronous (`httpx.Client`); async streaming is future work.
- `uncertain` results carry confidence `0.0` when the model output was
  malformed; otherwise the model's own confidence is preserved alongside
  the (non-confirming) verdict.
