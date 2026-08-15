import { MetricCard } from "../dashboard/MetricCard";
import type { ProofKpis } from "../../api/proof";

export interface ProofMetricCardsProps {
  kpis: ProofKpis;
}

export function ProofMetricCards({ kpis }: ProofMetricCardsProps) {
  return (
    <div className="pf-kpi-grid">
      <MetricCard
        label="Total Proof Results"
        available={kpis.total.available}
        value={kpis.total.value}
        supporting="sandbox verification records"
        to="/findings"
      />
      <MetricCard
        label="Verified"
        available={kpis.verified.available}
        value={kpis.verified.value}
        supporting="exploitability confirmed"
        tone="success"
      />
      <MetricCard
        label="Not Verified"
        available={kpis.not_verified.available}
        value={kpis.not_verified.value}
        supporting="not exploitable"
      />
      <MetricCard
        label="Blocked"
        available={kpis.blocked.available}
        value={kpis.blocked.value}
        supporting="blocked by sandbox policy"
        tone="warning"
      />
      <MetricCard
        label="Errors"
        available={kpis.errors.available}
        value={kpis.errors.value}
        supporting="harness failed"
        tone="danger"
      />
    </div>
  );
}
