import type { BenchmarkMetrics } from "../../api/benchmark";
import { Card } from "../ui/Card";
import { formatDuration, formatRatio } from "./benchmarkHelpers";

export interface MetricsComparisonProps {
  our: BenchmarkMetrics | null;
  semgrep: BenchmarkMetrics | null;
  ourDuration: number | null;
  semgrepDuration: number | null;
}

export function MetricsComparison({
  our,
  semgrep,
  ourDuration,
  semgrepDuration,
}: MetricsComparisonProps) {
  const rows: Array<[string, string, string]> = [
    ["Findings", metric(our?.total_findings), metric(semgrep?.total_findings)],
    ["TP", metric(our?.true_positives), metric(semgrep?.true_positives)],
    ["FP", metric(our?.false_positives), metric(semgrep?.false_positives)],
    ["FN", metric(our?.false_negatives), metric(semgrep?.false_negatives)],
    ["Precision", formatRatio(our?.precision ?? null), formatRatio(semgrep?.precision ?? null)],
    ["Recall", formatRatio(our?.recall ?? null), formatRatio(semgrep?.recall ?? null)],
    ["F1", formatRatio(our?.f1 ?? null), formatRatio(semgrep?.f1 ?? null)],
    [
      "Execution Time",
      ourDuration === null ? "\u2014" : formatDuration(ourDuration),
      semgrepDuration === null ? "\u2014" : formatDuration(semgrepDuration),
    ],
  ];

  return (
    <Card className="bmk-compare" aria-label="Benchmark Comparison">
      <table className="bmk-compare__table">
        <caption className="visually-hidden">Benchmark metric comparison</caption>
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">Our Scanner</th>
            <th scope="col">Semgrep</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, ours, theirs], index) => (
            <tr key={label}>
              <th scope="row">{label}</th>
              <td className="bmk-compare__value">{ours}</td>
              {semgrep === null ? (
                index === 0 ? (
                  <td className="bmk-compare__value" rowSpan={rows.length}>
                    Unavailable
                  </td>
                ) : null
              ) : (
                <td className="bmk-compare__value">{theirs}</td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function metric(value: number | undefined): string {
  return value === undefined ? "\u2014" : String(value);
}
