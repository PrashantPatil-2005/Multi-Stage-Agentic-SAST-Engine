import type { DashboardSlaSummary } from "../../api/dashboard";
import { Card } from "../ui/Card";
import "./dashboard.css";

export interface SlaSummaryProps {
  sla: DashboardSlaSummary;
}

function Stat({
  label,
  available,
  value,
  tone = "neutral",
}: {
  label: string;
  available: boolean;
  value: string | number;
  tone?: "neutral" | "danger";
}) {
  return (
    <div className="dash-stat">
      <span className={`dash-stat__value dash-stat__value--${tone}`}>
        {available ? value : "—"}
      </span>
      <span className="dash-stat__label">{label}</span>
    </div>
  );
}

export function SlaSummary({ sla }: SlaSummaryProps) {
  return (
    <Card title="SLA summary">
      {sla.available ? (
        <div className="dash-stats">
          <Stat label="Active" available value={sla.active} />
          <Stat
            label="Breached"
            available
            value={sla.breached}
            tone={sla.breached > 0 ? "danger" : "neutral"}
          />
          <Stat
            label="Highest-priority breach"
            available
            value={sla.highest_priority_breach ?? "None"}
          />
          <Stat label="Escalations" available value={sla.escalation_count} />
        </div>
      ) : (
        <p className="dash-empty">No SLA records yet.</p>
      )}
    </Card>
  );
}