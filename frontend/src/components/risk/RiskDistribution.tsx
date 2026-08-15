import { Card } from "../ui/Card";
import type { RiskBucket } from "../../api/risk";

export interface RiskDistributionProps {
  buckets: RiskBucket[];
}

export function RiskDistribution({ buckets }: RiskDistributionProps) {
  const max = Math.max(0, ...buckets.map((bucket) => bucket.count));

  return (
    <Card title="Risk Distribution" aria-label="Risk Distribution">
      {buckets.length === 0 ? (
        <p className="risk-empty-text">No risk assessments available</p>
      ) : (
        <ul className="risk-bars" aria-label="Findings by risk score">
          {buckets.map((bucket) => (
            <li className="risk-bar" key={bucket.label}>
              <div className="risk-bar__row">
                <BadgeScore label={bucket.label} />
                <span className="risk-bar__text">
                  {bucket.count} {bucket.count === 1 ? "finding" : "findings"}
                  {" \u00b7 "}
                  {bucket.percent}%
                </span>
              </div>
              <div
                className="risk-bar__track"
                role="img"
                aria-label={`Score ${bucket.label} — ${bucket.count} findings (${bucket.percent}%)`}
              >
                <div
                  className="risk-bar__fill risk-bar__fill--score"
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

function BadgeScore({ label }: { label: string }) {
  return <span className="risk-bar__label risk-bar__label--score">{label}</span>;
}
