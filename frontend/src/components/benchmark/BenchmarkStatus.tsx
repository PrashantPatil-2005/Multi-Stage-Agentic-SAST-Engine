import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import type { BenchmarkStatusKind } from "./benchmarkHelpers";
import { statusTone } from "./benchmarkHelpers";

export interface BenchmarkStatusProps {
  status: BenchmarkStatusKind | "Running";
  detail?: string | null;
}

export function BenchmarkStatus({ status, detail }: BenchmarkStatusProps) {
  return (
    <Card className="bmk-status" aria-label="Benchmark Status" aria-live="polite">
      <div className="bmk-status__row">
        <span className="bmk-status__label">Status</span>
        <Badge tone={statusTone(status)}>{status}</Badge>
      </div>
      {detail ? <p className="bmk-status__detail">{detail}</p> : null}
    </Card>
  );
}
