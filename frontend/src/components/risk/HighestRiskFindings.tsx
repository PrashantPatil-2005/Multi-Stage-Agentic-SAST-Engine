import type { KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import {
  factorLabel,
  priorityTone,
  proofLabel,
  slaStatusLabel,
  slaTone,
  validationLabel,
} from "./riskHelpers";
import type { RiskFindingRow } from "../../api/risk";

export interface HighestRiskFindingsProps {
  rows: RiskFindingRow[];
}

export function HighestRiskFindings({ rows }: HighestRiskFindingsProps) {
  const navigate = useNavigate();
  const top = rows.length > 0 ? rows[0] : null;

  const openFinding = (findingId: string) => navigate(`/findings/${findingId}`);

  const handleKeyDown = (findingId: string) => (event: KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openFinding(findingId);
    }
  };

  return (
    <Card title="Highest Risk Findings" aria-label="Highest Risk Findings">
      {rows.length === 0 ? (
        <p className="risk-empty-text">No risk assessments available</p>
      ) : (
        <>
          <div className="risk-table-scroll">
            <table className="risk-table">
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col">Risk Score</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Vulnerability</th>
                  <th scope="col">Repository</th>
                  <th scope="col">File</th>
                  <th scope="col">Validation</th>
                  <th scope="col">Proof</th>
                  <th scope="col">SLA</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
<tr
                    key={row.finding_id}
                    className="risk-table__row"
                    onClick={() => openFinding(row.finding_id)}
                    onKeyDown={handleKeyDown(row.finding_id)}
                    role="link"
                    tabIndex={0}
                    aria-label={`Open finding ${row.vulnerability_type}`}
                  >
                    <td>
                      <Badge tone={priorityTone(row.priority)}>{row.priority}</Badge>
                    </td>
                    <td className="risk-table__score">{row.risk_score}</td>
                    <td>{row.severity}</td>
                    <td>
                      <Link
                        className="risk-table__link"
                        to={`/findings/${row.finding_id}`}
                      >
                        {row.vulnerability_type}
                      </Link>
                    </td>
                    <td>{row.repository ?? "\u2014"}</td>
                    <td>{row.file}</td>
                    <td>{validationLabel(row.validation)}</td>
                    <td>{proofLabel(row.proof)}</td>
                    <td>
                      <Badge tone={slaTone(row.sla)}>{slaStatusLabel(row.sla)}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {top !== null && top.factors.length > 0 ? (
            <div className="risk-factors" aria-label="Risk factors for the top finding">
              <h4 className="risk-factors__title">
                Risk Factors — {top.vulnerability_type}
              </h4>
              <ul className="risk-factors__list">
                {top.factors.map((factor) => (
                  <li
                    className="risk-factors__item"
                    key={factor.name}
                    title={factor.description}
                  >
                    <span className="risk-factors__name">{factorLabel(factor.name)}</span>
                    <span className="risk-factors__points">
                      {factor.points > 0 ? `+${factor.points}` : factor.points}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </Card>
  );
}
