import { Link, useNavigate } from "react-router-dom";

import type { FindingListItem } from "../../api/findings";
import { Badge } from "../ui/Badge";
import {
  deriveDisplayStatus,
  formatConfidence,
  formatSlaRemaining,
  priorityTone,
  severityTone,
  slaStatus,
  statusTone,
  vulnLabel,
} from "./findingsHelpers";

export interface FindingRowProps {
  finding: FindingListItem;
}

export function FindingRow({ finding }: FindingRowProps) {
  const navigate = useNavigate();
  const status = deriveDisplayStatus(finding);
  const sla = slaStatus(finding);

  return (
    <tr onClick={() => navigate(`/findings/${finding.finding_id}`)}>
      <td>
        <Badge tone={priorityTone(finding.priority)}>
          {finding.priority ?? "—"}
        </Badge>
      </td>
      <td>
        <Badge tone={severityTone(finding.severity)}>
          {finding.severity.toUpperCase()}
        </Badge>
      </td>
      <td className="f-table__cell--wide">
        <Link
          className="f-table__vuln-link"
          to={`/findings/${finding.finding_id}`}
        >
          {vulnLabel(finding.vulnerability_type)}
        </Link>
      </td>
      <td>{finding.repository ?? "—"}</td>
      <td className="f-table__cell--wide">
        <span className="f-table__file" title={finding.file}>
          {finding.file}
        </span>
      </td>
      <td className="f-col-flow">
        <span className="f-table__flow">
          <span className="f-table__flow-snippet" title={finding.source_snippet}>
            {finding.source_snippet || "—"}
          </span>
          <span className="f-table__flow-arrow" aria-hidden="true">
            →
          </span>
          <span className="f-table__flow-snippet" title={finding.sink_snippet}>
            {finding.sink_snippet || "—"}
          </span>
        </span>
      </td>
      <td className="f-col-confidence f-table__confidence">
        {formatConfidence(finding.validation_confidence)}
      </td>
      <td>
        <Badge tone={sla.breached ? "danger" : "neutral"}>{sla.label}</Badge>
        {finding.sla.status === "active" && finding.sla.remaining_seconds !== null ? (
          <span className="f-table__sla-time">
            {formatSlaRemaining(finding.sla.remaining_seconds)}
          </span>
        ) : null}
      </td>
      <td>
        <Badge tone={statusTone(status)}>{status}</Badge>
      </td>
    </tr>
  );
}