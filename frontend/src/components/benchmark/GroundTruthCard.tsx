import { MetricCard } from "../dashboard/MetricCard";
import { Card } from "../ui/Card";

export interface GroundTruthCardProps {
  fixture: string;
  groundTruthCases: number;
  vulnerable: number | null;
  safe: number | null;
}

export function GroundTruthCard({
  fixture,
  groundTruthCases,
  vulnerable,
  safe,
}: GroundTruthCardProps) {
  return (
    <Card className="bmk-ground-truth" aria-label="Ground Truth">
      <div className="bmk-fixture">
        <span className="bmk-fixture__label">Fixture</span>
        <span className="bmk-fixture__value">{fixture}</span>
      </div>
      <div className="bmk-kpi-grid">
        <MetricCard
          label="Ground Truth Cases"
          available={true}
          value={groundTruthCases}
          supporting="cases"
        />
        <MetricCard
          label="Vulnerable Cases"
          available={vulnerable !== null}
          value={vulnerable ?? 0}
          supporting="cases"
        />
        <MetricCard
          label="Safe Cases"
          available={safe !== null}
          value={safe ?? 0}
          supporting="cases"
        />
      </div>
    </Card>
  );
}
