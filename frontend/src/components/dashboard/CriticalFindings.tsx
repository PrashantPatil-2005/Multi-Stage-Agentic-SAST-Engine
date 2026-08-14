import { Link } from "react-router-dom";

import type { DashboardFinding } from "../../api/dashboard";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import "./dashboard.css";

function priorityTone(priority: string | null): "danger" | "warning" | "neutral" {
  if (priority === "P0" || priority === "P1") return "danger";
  if (priority === "P2") return "warning";
  return "neutral";
}

function statusTone(status: string): "success" | "warning" | "neutral" {
  if (status === "approved" || status === "verified" || status === "true positive") {
    return "success";
  }
  if (status === "candidate" || status === "pending approval") return "warning";
  return "neutral";
}

export interface CriticalFindingsProps {
  findings: DashboardFinding[];
}

export function CriticalFindings({ findings }: CriticalFindingsProps) {
  return (
    <Card title="Critical findings">
      {findings.length === 0 ? (
        <p className="dash-empty">No findings assessed yet.</p>
      ) : (
        <ul className="dash-findings">
          {findings.map((finding) => (
            <li className="dash-findings__row" key={finding.finding_id}>
              <Link
                className="dash-findings__link"
                to={`/findings/${finding.finding_id}`}
              >
                <Badge tone={priorityTone(finding.priority)}>
                  {finding.priority ?? "—"}
                </Badge>
                <span className="dash-findings__vuln">
                  {finding.vulnerability_type}
                </span>
                <span className="dash-findings__file" title={finding.file}>
                  {finding.file}
                </span>
                <span className="dash-findings__repo">
                  {finding.repository ?? "—"}
                </span>
                <Badge tone={statusTone(finding.status)}>{finding.status}</Badge>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}