import type { DashboardVerification } from "../../api/dashboard";
import { Card } from "../ui/Card";
import "./dashboard.css";

function Row({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: number;
  tone?: "neutral" | "success" | "warning" | "danger";
}) {
  return (
    <div className="dash-verify__row">
      <span className="dash-verify__label">{label}</span>
      <span className={`dash-verify__value dash-verify__value--${tone}`}>
        {value}
      </span>
    </div>
  );
}

export interface VerificationSummaryProps {
  verification: DashboardVerification;
}

export function VerificationSummary({ verification }: VerificationSummaryProps) {
  const { available } = verification;
  return (
    <Card title="Verification">
      {available ? (
        <div className="dash-verify">
          <div className="dash-verify__group">
            <div className="dash-verify__group-title">Validation</div>
            <Row label="True positives" value={verification.true_positive} tone="success" />
            <Row label="False positives" value={verification.false_positive} />
            <Row label="Uncertain" value={verification.uncertain} tone="warning" />
          </div>
          <div className="dash-verify__group">
            <div className="dash-verify__group-title">Proof</div>
            <Row label="Verified" value={verification.verified} tone="success" />
            <Row label="Not verified" value={verification.not_verified} />
            <Row label="Blocked" value={verification.blocked} tone="warning" />
            <Row label="Errors" value={verification.errors} tone="danger" />
          </div>
        </div>
      ) : (
        <p className="dash-empty">No validation or proof results yet.</p>
      )}
    </Card>
  );
}