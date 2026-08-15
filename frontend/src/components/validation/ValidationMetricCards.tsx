import { MetricCard } from "../dashboard/MetricCard";
import type { ValidationKpis } from "../../api/validation";

export interface ValidationMetricCardsProps {
  kpis: ValidationKpis;
}

export function ValidationMetricCards({ kpis }: ValidationMetricCardsProps) {
  return (
    <div className="val-kpi-grid">
      <MetricCard
        label="Total Validations"
        available={kpis.total_validations.available}
        value={kpis.total_validations.value}
        supporting="LLM validation records"
        to="/findings"
      />
      <MetricCard
        label="True Positives"
        available={kpis.true_positives.available}
        value={kpis.true_positives.value}
        supporting="confirmed by LLM triage"
        tone="success"
      />
      <MetricCard
        label="False Positives"
        available={kpis.false_positives.available}
        value={kpis.false_positives.value}
        supporting="rejected by LLM triage"
      />
      <MetricCard
        label="Uncertain"
        available={kpis.uncertain.available}
        value={kpis.uncertain.value}
        supporting="needs manual review"
        tone="warning"
      />
      <MetricCard
        label="Pending / Not Validated"
        available={kpis.pending.available}
        value={kpis.pending.value}
        supporting="awaiting validation"
      />
    </div>
  );
}
