import { Link } from "react-router-dom";

import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import {
  formatTimestamp,
  priorityTone,
} from "./riskHelpers";
import type { SlaRow } from "../../api/risk";

export interface SlaBreachesProps {
  rows: SlaRow[];
}

export function SlaBreaches({ rows }: SlaBreachesProps) {
  return (
    <Card className="risk-breaches" title="SLA Breaches" aria-label="SLA Breaches list">
      {rows.length === 0 ? (
        <p className="risk-empty-text">No SLA breaches</p>
      ) : (
        <div className="risk-table-scroll">
          <table className="risk-table">
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Priority</th>
                <th scope="col">Due</th>
                <th scope="col">Breached At</th>
                <th scope="col">Escalation Level</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr className="risk-table__row--breach" key={row.finding_id}>
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
                  <td>{row.due_at !== null ? formatTimestamp(row.due_at) : "\u2014"}</td>
                  <td>
                    {row.breached_at !== null ? formatTimestamp(row.breached_at) : "\u2014"}
                  </td>
                  <td>{row.escalation_level}</td>
                  <td>
                    <Badge tone="danger">SLA BREACHED</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
