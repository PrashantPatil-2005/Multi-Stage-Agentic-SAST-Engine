import type { BenchmarkMetrics, BenchmarkResult } from "../../api/benchmark";
import { Card } from "../ui/Card";
import { formatDuration, formatRatio } from "./benchmarkHelpers";

export interface ScannerMetricsCardProps {
  title: string;
  metrics: BenchmarkMetrics | null;
  result: BenchmarkResult;
}

function metricValue(value: number | null): string {
  return value === null ? "\u2014" : String(value);
}

export function ScannerMetricsCard({
  title,
  metrics,
  result,
}: ScannerMetricsCardProps) {
  const rows: Array<[string, string]> = [
    ["Findings", metricValue(metrics?.total_findings ?? null)],
    ["True Positives", metricValue(metrics?.true_positives ?? null)],
    ["False Positives", metricValue(metrics?.false_positives ?? null)],
    ["False Negatives", metricValue(metrics?.false_negatives ?? null)],
    ["Precision", formatRatio(metrics?.precision ?? null)],
    ["Recall", formatRatio(metrics?.recall ?? null)],
    ["F1", formatRatio(metrics?.f1 ?? null)],
    [
      "Execution Time",
      result.duration_ms === null
        ? "\u2014"
        : formatDuration(result.duration_ms),
    ],
  ];

  return (
    <Card className="bmk-metrics" aria-label={title}>
      <table className="bmk-metric-table">
        <caption className="visually-hidden">{`${title} metrics`}</caption>
        <thead>
          <tr>
            <th scope="col">Metric</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label}>
              <th scope="row">{label}</th>
              <td className="bmk-metric-table__value">{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
