import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { priorityTone } from "./riskHelpers";
import type { PriorityBucket } from "../../api/risk";

export interface PriorityDistributionProps {
  buckets: PriorityBucket[];
}

export function PriorityDistribution({ buckets }: PriorityDistributionProps) {
  const max = Math.max(0, ...buckets.map((bucket) => bucket.count));

  return (
    <Card title="Priority Distribution" aria-label="Priority Distribution">
      {buckets.length === 0 ? (
        <p className="risk-empty-text">No risk assessments available</p>
      ) : (
        <ul className="risk-bars" aria-label="Findings by priority">
          {buckets.map((bucket) => (
            <li className="risk-bar" key={bucket.priority}>
              <div className="risk-bar__row">
                <Badge
                  className="risk-bar__label"
                  tone={priorityTone(bucket.priority)}
                >
                  {bucket.priority}
                </Badge>
                <span className="risk-bar__text">
                  {bucket.count} {bucket.count === 1 ? "finding" : "findings"}
                  {" \u00b7 "}
                  {bucket.percent}%
                </span>
              </div>
              <div
                className="risk-bar__track"
                role="img"
                aria-label={`${bucket.priority} — ${bucket.count} findings (${bucket.percent}%)`}
              >
                <div
                  className="risk-bar__fill"
                  style={{
                    width: max > 0 ? `${Math.round((bucket.count / max) * 100)}%` : "0%",
                  }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
