import { MetricCard } from "../dashboard/MetricCard";
import type { RiskKpis } from "../../api/risk";

export interface RiskMetricCardsProps {
  kpis: RiskKpis;
}

export function RiskMetricCards({ kpis }: RiskMetricCardsProps) {
  return (
    <div className="risk-kpi-grid">
      <MetricCard
        label="Total Risk Assessments"
        available={kpis.total_assessments.available}
        value={kpis.total_assessments.value}
        supporting="findings with risk scores"
        to="/findings"
      />
      <MetricCard
        label="Critical / P0"
        available={kpis.critical_p0.available}
        value={kpis.critical_p0.value}
        supporting="highest-priority issues"
        tone="danger"
      />
      <MetricCard
        label="High / P1"
        available={kpis.high_p1.available}
        value={kpis.high_p1.value}
        supporting="urgent issues"
        tone="warning"
      />
      <MetricCard
        label="Active SLAs"
        available={kpis.active_slas.available}
        value={kpis.active_slas.value}
        supporting="deadlines tracking"
      />
      <MetricCard
        label="SLA Breaches"
        available={kpis.sla_breaches.available}
        value={kpis.sla_breaches.value}
        supporting="past remediation deadline"
        tone="danger"
      />
      <MetricCard
        label="Escalations"
        available={kpis.escalations.available}
        value={kpis.escalations.value}
        supporting="escalation events recorded"
        tone="warning"
      />
    </div>
  );
}
