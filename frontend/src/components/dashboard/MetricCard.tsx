import { Link } from "react-router-dom";

import { Card } from "../ui/Card";
import "./dashboard.css";

export interface MetricCardProps {
  label: string;
  available: boolean;
  value: number;
  supporting: string;
  tone?: "neutral" | "success" | "warning" | "danger";
  to?: string;
}

export function MetricCard({
  label,
  available,
  value,
  supporting,
  tone = "neutral",
  to,
}: MetricCardProps) {
  const content = (
    <div className="dash-kpi">
      <div className={`dash-kpi__value dash-kpi__value--${tone}`}>
        {available ? value : "—"}
      </div>
      <div className="dash-kpi__label">{label}</div>
      <div className="dash-kpi__supporting">
        {available ? supporting : "No data available"}
      </div>
    </div>
  );

  return (
    <Card
      className={`dash-kpi-card${to ? " dash-kpi-card--link" : ""}`}
      aria-label={label}
    >
      {to ? <Link to={to}>{content}</Link> : content}
    </Card>
  );
}