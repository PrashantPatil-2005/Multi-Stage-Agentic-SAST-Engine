import type { KeyboardEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import type { ProofRow } from "../../api/proof";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { ProofSummary } from "./ProofSummary";
import {
  confidenceLabel,
  formatDate,
  formatDuration,
  priorityTone,
  proofStatusLabel,
  proofTone,
  shortFindingId,
  verdictLabel,
  verdictTone,
} from "./proofHelpers";

export interface ProofTableProps {
  rows: ProofRow[];
}

export function ProofTable({ rows }: ProofTableProps) {
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
    <Card title="Proof Results" aria-label="Proof Results">
      {rows.length === 0 ? (
        <p className="pf-empty-text">No proof results</p>
      ) : (
        <div className="pf-table-scroll">
          <table className="pf-table">
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Vulnerability</th>
                <th scope="col">Priority</th>
                <th scope="col">Validation</th>
                <th scope="col">Proof Status</th>
                <th scope="col">Confidence</th>
                <th scope="col">Duration</th>
                <th scope="col">Created At</th>
                <th scope="col">Summary</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.finding_id}
                  className="pf-table__row"
                  onClick={() => openFinding(row.finding_id)}
                  onKeyDown={handleKeyDown(row.finding_id)}
                  role="link"
                  tabIndex={0}
                  aria-label={`Open finding ${row.vulnerability_type ?? row.finding_id}`}
                >
                  <td>
                    <Link
                      className="pf-table__link"
                      to={`/findings/${row.finding_id}`}
                    >
                      {shortFindingId(row.finding_id)}
                    </Link>
                  </td>
                  <td>{row.vulnerability_type ?? "\u2014"}</td>
                  <td>
                    <Badge tone={priorityTone(row.priority ?? "")}>
                      {row.priority ?? "\u2014"}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={verdictTone(row.validation)}>
                      {verdictLabel(row.validation)}
                    </Badge>
                  </td>
                  <td>
                    <Badge tone={proofTone(row.status)}>
                      {proofStatusLabel(row.status)}
                    </Badge>
                  </td>
                  <td className="pf-table__mono">
                    {confidenceLabel(row.confidence)}
                  </td>
                  <td className="pf-table__mono">{formatDuration(row.duration_ms)}</td>
                  <td>{formatDate(row.created_at)}</td>
                  <td>
                    <ProofSummary row={row} />
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
