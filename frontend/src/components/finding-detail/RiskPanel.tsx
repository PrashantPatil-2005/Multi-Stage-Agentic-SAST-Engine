import type { FindingDetail, RiskFactor } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { severityTone } from "../findings/findingsHelpers";
import { formatTimestamp } from "./detailHelpers";

function FactorRow({ factor }: { factor: RiskFactor }) {
  return (
    <li className="fd-factors__item">
      <div className="fd-factors__head">
        <span className="fd-factors__name">{factor.name}</span>
        <span className="fd-factors__value">{factor.value}</span>
        <span className="fd-factors__points">{factor.points} pts</span>
      </div>
      <p className="fd-factors__description">{factor.description}</p>
    </li>
  );
}

export function RiskPanel({
  detail,
  onAssess,
  assessing = false,
  riskError = null,
}: {
  detail: FindingDetail;
  onAssess?: () => void;
  assessing?: boolean;
  riskError?: string | null;
}) {
  const risk = detail.risk;
  const interactive = typeof onAssess === "function";

  return (
    <Card title="Risk">
      {!risk ? (
        <div className="fd-panel__body">
          <p className="fd-panel__empty">Risk assessment not available</p>
          {interactive && riskError ? (
            <p className="fd-panel__error" role="alert">
              Unable to assess risk: {riskError}
            </p>
          ) : null}
          {interactive ? (
            <div className="fd-panel__actions">
              <Button
                size="sm"
                variant="secondary"
                disabled={assessing}
                onClick={onAssess}
              >
                {assessing ? "Assessing Risk\u2026" : "Assess Risk"}
              </Button>
            </div>
          ) : null}
        </div>
      ) : (
        <div className="fd-panel__body">
          <div className="fd-risk__score-row">
            <span className="fd-risk__score">
              {risk.risk_score}
              <span className="fd-risk__score-max"> / 100</span>
            </span>
            <div className="fd-risk__badges">
              <Badge tone="info">{risk.priority}</Badge>
              <Badge tone={severityTone(risk.severity)}>
                {risk.severity.toUpperCase()}
              </Badge>
            </div>
          </div>
          <p className="fd-risk__assessed">
            Assessed {formatTimestamp(risk.assessed_at)}
          </p>
          {interactive ? (
            <p className="fd-risk__available" role="status">
              Risk Assessment Available
            </p>
          ) : null}
          <h4 className="fd-risk__factors-title">Risk Factors</h4>
          <ul className="fd-factors">
            {risk.factors.map((factor) => (
              <FactorRow key={`${factor.name}:${factor.value}`} factor={factor} />
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}