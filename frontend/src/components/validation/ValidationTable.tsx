import type { KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import type { ValidationRow } from "../../api/validation";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { ValidationReasoning } from "./ValidationReasoning";
import {
  confidenceLabel,
  formatDate,
  priorityTone,
  proofStatusLabel,
  proofTone,
  shortFindingId,
  verdictLabel,
  verdictTone,
} from "./validationHelpers";

export interface ValidationTableProps {
  rows: ValidationRow[];
}

export function ValidationTable({ rows }: ValidationTableProps) {
  const navigate = useNavigate();

  const openFinding = (findingId: string) => navigate(`/findings/${findingId}`);

  const handleKeyDown =
    (findingId: string) => (event: KeyboardEvent<HTMLTableRowElement>) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openFinding(findingId);
      }
    };

  return (
    <Card title="Validation Results" aria-label="Validation Results">
      {rows.length === 0 ? (
        <p className="val-empty-text">No validation results</p>
      ) : (
        <div className="val-table-scroll">
          <table className="val-table">
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Vulnerability</th>
                <th scope="col">Severity</th>
                <th scope="col">Priority</th>
                <th scope="col">Confidence</th>
                <th scope="col">Verdict</th>
                <th scope="col">Validated At</th>
                <th scope="col">Proof Status</th>
                <th scope="col">Reasoning</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.finding_id}
                  className="val-table__row"
                  onClick={() => openFinding(row.finding_id)}
                  onKeyDown={handleKeyDown(row.finding_id)}
                  role="link"
                  tabIndex={0}
                  aria-label={`Open finding ${row.vulnerability_type ?? row.finding_id}`}
                >
                  <td>
                    <Link
                      className="val-table__link"
                      to={`/findings/${row.finding_id}`}
                    >
                      {shortFindingId(row.finding_id)}
                    </Link>
                  </td>
                  <td>{row.vulnerability_type ?? "\u2014"}</td>
                  <td>{row.severity ?? "\u2014"}</td>
                  <td>
                    <Badge tone={priorityTone(row.priority ?? "")}>
                      {row.priority ?? "\u2014"}
                    </Badge>
                  </td>
                  <td className="val-table__mono">
                    {confidenceLabel(row.confidence)}
                  </td>
                  <td>
                    <Badge tone={verdictTone(row.verdict)}>
                      {verdictLabel(row.verdict)}
                    </Badge>
                  </td>
                  <td>{formatDate(row.validated_at)}</td>
                  <td>
                    <Badge tone={proofTone(row.proof_status)}>
                      {proofStatusLabel(row.proof_status)}
                    </Badge>
                  </td>
                  <td>
                    <ValidationReasoning row={row} />
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
