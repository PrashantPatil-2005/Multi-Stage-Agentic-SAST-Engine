import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import type { SlaOverview as SlaOverviewData } from "../../api/risk";

export interface SlaOverviewProps {
  overview: SlaOverviewData;
}

export function SlaOverview({ overview }: SlaOverviewProps) {
  const entries = [
    { label: "Active", value: overview.active, tone: "info" as const },
    { label: "Breached", value: overview.breached, tone: "danger" as const },
    { label: "Resolved", value: overview.resolved, tone: "success" as const },
    { label: "No SLA", value: overview.no_sla, tone: "neutral" as const },
  ];

  return (
    <Card title="SLA Overview" aria-label="SLA Overview">
      {overview.available ? (
        <ul className="risk-sla-overview">
          {entries.map((entry) => (
            <li className="risk-sla-overview__item" key={entry.label}>
              <span className="risk-sla-overview__value">{entry.value}</span>
              <Badge tone={entry.tone}>{entry.label}</Badge>
            </li>
          ))}
        </ul>
      ) : (
        <p className="risk-empty-text">No SLA data available</p>
      )}
    </Card>
  );
}
