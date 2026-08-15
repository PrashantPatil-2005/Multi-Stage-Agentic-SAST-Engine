import type { FindingDetail, RiskFactor } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
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

export function RiskPanel({ detail }: { detail: FindingDetail }) {
  const risk = detail.risk;

  return (
    <Card title="Risk">
      {!risk ? (
        <p className="fd-panel__empty">Risk assessment not available</p>
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
