import { Link } from "react-router-dom";

import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { formatTimestamp } from "./riskHelpers";
import type { EscalationRow } from "../../api/risk";

export interface EscalationTimelineProps {
  rows: EscalationRow[];
}

export function EscalationTimeline({ rows }: EscalationTimelineProps) {
  return (
    <Card title="Escalation Activity" aria-label="Escalation Activity">
      {rows.length === 0 ? (
        <p className="risk-empty-text">No escalation events</p>
      ) : (
        <ol className="risk-timeline" aria-label="Escalation events">
          {rows.map((row, index) => (
            <li className="risk-timeline__item" key={`${row.finding_id}-${index}`}>
              <div className="risk-timeline__levels">
                <Badge tone="neutral">Level {row.previous_level}</Badge>
                <span className="risk-timeline__arrow" aria-hidden="true">
                  {"\u2192"}
                </span>
                <Badge tone="danger">Level {row.new_level}</Badge>
              </div>
              <div className="risk-timeline__body">
                <p className="risk-timeline__reason">{row.reason}</p>
                <p className="risk-timeline__meta">
                  <Link
                    className="risk-table__link"
                    to={`/findings/${row.finding_id}`}
                  >
                    {row.vulnerability_type ?? row.finding_id}
                  </Link>
                  {row.priority !== null ? (
                    <>
                      {" \u00b7 "}
                      <Badge tone="neutral">{row.priority}</Badge>
                    </>
                  ) : null}
                </p>
              </div>
              <time className="risk-timeline__time" dateTime={row.created_at}>
                {formatTimestamp(row.created_at)}
              </time>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}
