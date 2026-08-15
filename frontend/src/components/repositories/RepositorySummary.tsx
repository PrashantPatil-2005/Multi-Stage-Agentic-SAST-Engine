import { MetricCard } from "../dashboard/MetricCard";

export interface RepositorySummaryProps {
  repositoryCount: number;
  findingCount: number;
  assessedCount: number;
  breachCount: number;
}

export function RepositorySummary({
  repositoryCount,
  findingCount,
  assessedCount,
  breachCount,
}: RepositorySummaryProps) {
  return (
    <div className="repo-kpi-grid">
      <MetricCard
        label="Repositories"
        available={repositoryCount > 0}
        value={repositoryCount}
        supporting="registered projects"
      />
      <MetricCard
        label="Total Findings"
        available={findingCount > 0}
        value={findingCount}
        supporting="attributed to repositories"
        to="/findings"
      />
      <MetricCard
        label="With Risk Assessment"
        available={assessedCount > 0}
        value={assessedCount}
        supporting="highest-priority findings scored"
        tone="warning"
        to="/risk"
      />
      <MetricCard
        label="SLA Breaches"
        available={breachCount > 0}
        value={breachCount}
        supporting="repositories with breached deadlines"
        tone="danger"
        to="/risk"
      />
    </div>
  );
}
