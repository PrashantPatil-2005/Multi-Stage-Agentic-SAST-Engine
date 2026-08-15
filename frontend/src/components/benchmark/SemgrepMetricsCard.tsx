import type { BenchmarkMetrics, BenchmarkResult } from "../../api/benchmark";
import { Card } from "../ui/Card";
import { ScannerMetricsCard } from "./ScannerMetricsCard";

export interface SemgrepMetricsCardProps {
  result: BenchmarkResult;
  metrics: BenchmarkMetrics | null;
}

export function SemgrepMetricsCard({
  result,
  metrics,
}: SemgrepMetricsCardProps) {
  if (!result.available) {
    return (
      <Card className="bmk-metrics" aria-label="Semgrep">
        <div className="bmk-unavailable">
          <strong className="bmk-unavailable__title">
            SEMGREP UNAVAILABLE
          </strong>
          <p className="bmk-unavailable__text">
            Semgrep is not installed/configured in this environment.
          </p>
          {result.error ? (
            <p className="bmk-unavailable__detail">{result.error}</p>
          ) : null}
        </div>
      </Card>
    );
  }

  if (result.error !== null) {
    return (
      <Card className="bmk-metrics" aria-label="Semgrep">
        <div className="bmk-unavailable">
          <strong className="bmk-unavailable__title">SEMGREP FAILED</strong>
          <p className="bmk-unavailable__text">
            Semgrep ran but did not complete successfully.
          </p>
          <p className="bmk-unavailable__detail">{result.error}</p>
        </div>
      </Card>
    );
  }

  return <ScannerMetricsCard title="Semgrep" metrics={metrics} result={result} />;
}
