import { Link } from "react-router-dom";

import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import {
  formatDate,
  formatRemaining,
  formatTimestamp,
  priorityTone,
  slaStatusLabel,
} from "./riskHelpers";
import type { SlaRow } from "../../api/risk";

export interface SlaTableProps {
  rows: SlaRow[];
}

export function SlaTable({ rows }: SlaTableProps) {
  return (
    <Card title="Active SLAs" aria-label="Active SLA records">
      {rows.length === 0 ? (
        <p className="risk-empty-text">No active SLAs</p>
      ) : (
        <div className="risk-table-scroll">
          <table className="risk-table">
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Priority</th>
                <th scope="col">Started</th>
                <th scope="col">Due</th>
                <th scope="col">Status</th>
                <th scope="col">Escalation Level</th>
                <th scope="col">Remaining</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.finding_id}>
                  <td>
                    <Link
                      className="risk-table__link"
                      to={`/findings/${row.finding_id}`}
                    >
                      {row.vulnerability_type ?? row.finding_id}
                    </Link>
                  </td>
                  <td>
                    <Badge tone={priorityTone(row.priority)}>{row.priority}</Badge>
                  </td>
                  <td>{formatDate(row.started_at)}</td>
                  <td>{row.due_at !== null ? formatTimestamp(row.due_at) : "\u2014"}</td>
                  <td>
                    <Badge tone="info">{slaStatusLabel(row.status)}</Badge>
                  </td>
                  <td>{row.escalation_level}</td>
                  <td>{formatRemaining(row.remaining_seconds)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
