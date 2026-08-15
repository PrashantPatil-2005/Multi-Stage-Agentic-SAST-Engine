/* Typed API client for the Benchmark page. Mirrors the backend response
   models in app/benchmark/models.py and app/api/benchmark_models.py.
   The page is read-only; the only write operation is the intended backend
   execution endpoint POST /api/benchmarks/semgrep, which runs our engine
   and Semgrep against the controlled fixture server-side. The frontend
   never invokes Semgrep, shells or filesystem access itself. */

import { fetchJson } from "./dashboard";

export interface BenchmarkFinding {
  tool: string;
  vulnerability_type: string;
  file: string;
  line: number;
  function: string | null;
  message: string;
  fingerprint: string;
}

export interface BenchmarkResult {
  tool: string;
  available: boolean;
  findings: BenchmarkFinding[];
  duration_ms: number | null;
  error: string | null;
}

export interface BenchmarkMetrics {
  tool: string;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  precision: number | null; // 0-1 ratio, null when denominator is zero
  recall: number | null;
  f1: number | null;
  total_findings: number;
}

export interface BenchmarkComparison {
  shared_findings: BenchmarkFinding[];
  ours_only: BenchmarkFinding[];
  semgrep_only: BenchmarkFinding[];
  shared_vulnerability_types: string[];
  safe_cases_detected_incorrectly: string[];
}

export interface BenchmarkReport {
  benchmark_id: string;
  fixture: string;
  ground_truth_count: number;
  our_result: BenchmarkResult;
  semgrep_result: BenchmarkResult;
  metrics: BenchmarkMetrics[];
  comparison: BenchmarkComparison;
  created_at: string;
}

export interface BenchmarkSummary {
  benchmark_id: string;
  fixture: string;
  created_at: string;
  semgrep_available: boolean;
  semgrep_error: string | null;
  our_f1: number | null;
  semgrep_f1: number | null;
  ground_truth_cases: number;
  vulnerable_cases: number | null;
  safe_cases: number | null;
}

export interface BenchmarkList {
  has_reports: boolean;
  reports: BenchmarkSummary[];
}

export function getBenchmarkList(): Promise<BenchmarkList> {
  return fetchJson<BenchmarkList>("/api/benchmarks");
}

export function getBenchmarkReport(benchmarkId: string): Promise<BenchmarkReport> {
  return fetchJson<BenchmarkReport>(`/api/benchmarks/${benchmarkId}`);
}

export function runBenchmark(fixture: string): Promise<BenchmarkReport> {
  return fetch("/api/benchmarks/semgrep", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fixture }),
  }).then((response) => {
    if (!response.ok) {
      throw new Error(`request failed: /api/benchmarks/semgrep (${response.status})`);
    }
    return response.json() as Promise<BenchmarkReport>;
  });
}
