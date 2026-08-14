# Semgrep Benchmark (optional evaluation path)

Objectively compares **our SAST engine vs Semgrep** on the same controlled
fixture repositories. This module is a **benchmark only**: it never modifies
our scanner, findings, risk, validation, or proof, and it is **not part of the
production pipeline**.

```
Fixture Repository
       ↓
   ┌───────────────┐
   │               │
Our Scanner     Semgrep   (optional, offline)
   │               │
   ↓               ↓
Our Findings   Semgrep Findings
   │               │
   └───────┬───────┘
           ↓
     Benchmark Engine
           ↓
      Comparison Report
```

## Ground truth

`ground_truth.py` declares explicit cases for `vulnerable_python_app`
(8 cases: 5 vulnerable, 3 safe) with `case_id`, `file`, `function`,
`vulnerability_type`, `expected_vulnerable`, source/sink descriptions and
lines. Ground truth is authoritative for metrics and is **never inferred from
what either scanner reports**.

Safe cases are deliberate: `get_user_safe` (parameterized SQL), `fetch_safe`
(constant URL), `run_command_safe` (constant command). A tool reporting a
safe case counts a false positive.

## Semgrep dependency

Semgrep is **optional**. `SemgrepRunner.is_available()` detects the CLI.
When unavailable:

- the benchmark returns a clear `unavailable` result with an explanatory error;
- no fake findings are ever presented as real results;
- the application does not crash;
- the full test suite runs against `FakeSemgrepRunner` instead.

## Offline behavior

- Rules come from the bundled, repository-independent set in
  `app/benchmark/rules/` (SQLi, command injection, SSRF).
- `--config auto` / registry downloads are never used → zero network.
- The target fixture is only *scanned* by Semgrep, never imported or executed.

## Matching algorithm

`BenchmarkMatcher` never compares finding IDs. Two findings match when:

1. same file (basename),
2. same canonical vulnerability type,
3. line distance ≤ tolerance (default 3) **or** equal function names.

Greedy one-to-one matching; the small tolerance prevents merging unrelated
findings. Ground-truth matching uses the same rules against a case's
source/sink lines and function.

## Metrics

TP / FP / FN against ground truth, then precision, recall, F1
(zero denominators → `null`, never misleading values). Execution times come
from monotonic timers (scanner, Semgrep, total).

## Limitations

- Fixture metrics are **engineering comparisons, not a scientific study**:
  a single run, a small controlled corpus, and only 3 vulnerability classes.
  They measure agreement with the fixture ground truth — they are **not** a
  claim of real-world accuracy.
- Bundled rules are simplified; real Semgrep registry rules may behave
  differently.
- Semgrep may report additional sites (e.g. `shell=True` with a constant
  command); that is expected and counted as false positives.
- Findings are matched structurally (line/function), so very close distinct
  vulnerabilities in the same function can be confused — the tolerance is
  kept small on purpose.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/benchmarks/semgrep` | run benchmark on a fixture (`{"fixture": "vulnerable_python_app"}`) |
| GET | `/api/benchmarks/{benchmark_id}` | stored report |

Errors: 404 (unknown fixture / benchmark), 422 (invalid fixture name).

## Security properties (tested)

- Subprocess uses an **argument list**, never `shell=True`.
- Command is built from trusted arguments; malicious fixture names
  (`;`, `--config auto`, path separators) are rejected before execution.
- Hard timeout on the Semgrep process; stdout/stderr size is bounded.
- No network, no registry rules, no repository-supplied configuration.
- The benchmark leaves finding/validation/proof/risk stores untouched.