# Cross-Repository Finding Deduplication

Stage: **DEDUP** — runs after SCAN, before VALIDATE/PROVE.

## Why it is needed

The same underlying vulnerability can appear in several repositories, at
different file paths and line numbers, and with different variable names
after refactoring or code movement. Treating each occurrence as a brand-new
issue floods the VALIDATE/PROVE stages with identical work and hides the fact
that one fix (or one false positive) applies to N findings.

Deduplication gives every structurally identical finding the same identity,
so operators and the LLM can treat one representative per group.

## Fingerprint design

`FindingFingerprintBuilder` produces a `FindingFingerprint` whose `value` is

```
SHA-256(structural_signature)
```

and whose `structural_signature` is the explainable string

```
vulnerability_type|source_category|sink_category|
normalized_source|normalized_sink|taint_structure
```

Example (the two fixture repositories):

```
sql_injection|request_param|sql_execute|
_n_.args.get ( _lit_ )|_n_.execute ( _n_ )|source->string_construction->sink
```

The fingerprint **never** includes:

- repository id
- absolute file path
- line number
- finding id
- timestamp

### Normalization

Snippets are re-tokenized and mapped to a fixed vocabulary:

| token | normalized to |
|---|---|
| identifier | `_n_` |
| attribute after a dot | kept: `cursor.execute` -> `_n_.execute` |
| string / number / f-string literal | `_lit_` |
| operator / delimiter | kept as-is |

Whitespace is collapsed. Literal values are replaced by `_lit_`, so the
fingerprint contains **structural metadata only** — no source-code secrets,
API keys, passwords or credentials can end up in it.

The vulnerability type, source category and sink category are never
normalized away; f-string vs concatenation vs `.format()` construction all
collapse to the same `string_construction` step type, which is what makes
the two example repositories match.

## Grouping

`DeduplicationService.deduplicate(findings)` does a single dict pass:

```
fingerprint -> bucket
```

so runtime is **O(n)** in the number of findings — no pairwise comparison.

Each bucket becomes one `DeduplicationGroup`:

- `fingerprint` / `structural_signature`
- `canonical_finding_id` — deterministic: the member with the
  lexicographically smallest finding id
- `member_finding_ids` — every original finding id (sorted by id)
- `occurrence_count` — number of members
- `repositories` — unique repository labels, derived from the file path
  (parent directory name, or the file name for top-level files)
- `vulnerability_type`, `representative_finding` (the canonical finding)
- `match_reasons` — why the group was formed

The service **never deletes findings and never mutates a
`CandidateFinding`**; every input finding survives inside exactly one group.

## False-merge tradeoff

Grouping happens at the structural level only. Two SQL injection findings
with the same source category, sink category and step structure merge even
when their query *text* differs (`users` vs `records`) — that is precisely
what the cross-repository example requires. To keep merging conservative:

- different vulnerability types never merge
- different source or sink categories never merge
- different normalized sink patterns (e.g. `execute` vs `executescript`,
  or an extra parameter) never merge
- different taint step structures never merge

False merging is treated as worse than missing a duplicate; when in doubt,
the fingerprint differs and the findings stay separate.

## Cross-repository behavior

Because the fingerprint ignores repository, file, line and ids, scanning
`repository_a` and `repository_b` of the test fixture produces one group
with `occurrence_count = 2`. The only path-dependent input is the
*repository label* used for reporting (`repositories`), which is
approximated from the file path since findings do not carry a repository id.

## API

- `POST /api/deduplicate` — body `{"finding_ids": [...]}`; looks findings up
  in the finding store (404 listing unknown ids), returns a
  `DeduplicationResult`.
- `GET /api/deduplication/{fingerprint}` — returns the group from the most
  recent deduplication run (404 when unknown).

## Persistence

Groups are kept in an in-memory registry for fast reads and mirrored into
SQLite (`deduplication_groups`) when a session factory is configured, so a
backend restart keeps the latest run's groups (same convention as the other
pipeline stores; see `app/db/persistence.py`). A new deduplication run
replaces the persisted groups.

## Limitations

- Repository identity is approximated from the file path, not from a real
  repository id (findings do not carry one).
- Literal query text is deliberately not part of the fingerprint, so two
  structurally identical but textually different queries merge (see
  false-merge tradeoff above).
- Inter-procedural shapes are not normalized: a flow with an extra
  `assignment` step has a different taint structure and stays separate.