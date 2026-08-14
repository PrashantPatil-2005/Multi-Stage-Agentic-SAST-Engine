import type { DashboardActivityItem } from "../../api/dashboard";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import "./dashboard.css";

function kindTone(kind: string): "neutral" | "success" | "warning" | "danger" | "info" {
  switch (kind) {
    case "project_created":
      return "neutral";
    case "finding_validated":
      return "info";
    case "proof_completed":
      return "success";
    case "sla_breached":
      return "danger";
    case "approval_updated":
      return "warning";
    default:
      return "neutral";
  }
}

function kindLabel(kind: string): string {
  switch (kind) {
    case "project_created":
      return "Project";
    case "finding_validated":
      return "Validated";
    case "proof_completed":
      return "Proof";
    case "sla_breached":
      return "SLA breach";
    case "approval_updated":
      return "Approval";
    default:
      return kind;
  }
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export interface RecentActivityProps {
  items: DashboardActivityItem[];
}

export function RecentActivity({ items }: RecentActivityProps) {
  return (
    <Card title="Recent activity">
      {items.length === 0 ? (
        <p className="dash-empty">No recent activity.</p>
      ) : (
        <ul className="dash-activity">
          {items.map((item) => (
            <li className="dash-activity__item" key={`${item.kind}-${item.created_at}`}>
              <Badge tone={kindTone(item.kind)}>{kindLabel(item.kind)}</Badge>
              <div className="dash-activity__body">
                <span className="dash-activity__message">{item.message}</span>
                <span className="dash-activity__time">
                  {formatTime(item.created_at)}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}