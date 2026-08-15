import type { KeyboardEvent } from "react";

import type { BenchmarkSummary } from "../../api/benchmark";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import {
  formatDate,
  formatRatio,
  shortBenchmarkId,
  statusFromSummary,
  statusTone,
} from "./benchmarkHelpers";

export interface BenchmarkHistoryProps {
  summaries: BenchmarkSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function BenchmarkHistory({
  summaries,
  selectedId,
  onSelect,
}: BenchmarkHistoryProps) {
  const handleKeyDown = (id: string) => (event: KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(id);
    }
  };

  return (
    <Card className="bmk-history" aria-label="Benchmark Runs">
      <div className="bmk-table-scroll">
        <table className="bmk-table">
          <caption className="visually-hidden">Benchmark runs</caption>
          <thead>
            <tr>
              <th scope="col">Benchmark ID</th>
              <th scope="col">Fixture</th>
              <th scope="col">Created At</th>
              <th scope="col">Status</th>
              <th scope="col">Our F1</th>
              <th scope="col">Semgrep F1</th>
            </tr>
          </thead>
          <tbody>
            {summaries.map((summary) => {
              const selected = summary.benchmark_id === selectedId;
              const status = statusFromSummary(summary);
              return (
                <tr
                  key={summary.benchmark_id}
                  role="button"
                  tabIndex={0}
                  aria-label={`View report ${shortBenchmarkId(summary.benchmark_id)}`}
                  aria-current={selected ? "true" : undefined}
                  className={`bmk-history__row${selected ? " bmk-history__row--selected" : ""}`}
                  onClick={() => onSelect(summary.benchmark_id)}
                  onKeyDown={handleKeyDown(summary.benchmark_id)}
                >
                  <td className="bmk-table__mono">
                    {shortBenchmarkId(summary.benchmark_id)}
                  </td>
                  <td className="bmk-table__mono">{summary.fixture}</td>
                  <td>{formatDate(summary.created_at)}</td>
                  <td>
                    <Badge tone={statusTone(status)}>{status}</Badge>
                  </td>
                  <td className="bmk-table__mono">
                    {formatRatio(summary.our_f1)}
                  </td>
                  <td className="bmk-table__mono">
                    {formatRatio(summary.semgrep_f1)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
