/* Presentation helpers for the Benchmark page. Values are formatted from
   backend data only - metrics and f1 are never computed here. */

import { formatDuration } from "../proof/proofHelpers";
import { formatDate } from "../validation/validationHelpers";

export { formatDate, formatDuration };

export function formatRatio(value: number | null): string {
  if (value === null) return "\u2014";
  const percent = Math.round(value * 10000) / 100;
  return `${percent}%`;
}

export function shortBenchmarkId(id: string): string {
  return id.length > 13 ? `${id.slice(0, 12)}\u2026` : id;
}

export type BenchmarkStatusKind = "Completed" | "Failed" | "Semgrep Unavailable";

export function statusFromResult(result: {
  available: boolean;
  error: string | null;
}): BenchmarkStatusKind {
  if (!result.available) return "Semgrep Unavailable";
  if (result.error !== null) return "Failed";
  return "Completed";
}

export function statusFromSummary(summary: {
  semgrep_available: boolean;
  semgrep_error: string | null;
}): BenchmarkStatusKind {
  if (!summary.semgrep_available) return "Semgrep Unavailable";
  if (summary.semgrep_error !== null) return "Failed";
  return "Completed";
}

export function statusTone(
  status: BenchmarkStatusKind | "Running",
): "success" | "warning" | "danger" | "neutral" {
  if (status === "Completed") return "success";
  if (status === "Semgrep Unavailable") return "warning";
  if (status === "Failed") return "danger";
  return "neutral";
}
