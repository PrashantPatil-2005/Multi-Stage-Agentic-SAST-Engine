import { Link } from "react-router-dom";

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

export interface FindingCardProps {
  finding: FindingListItem;
}

export function FindingCard({ finding }: FindingCardProps) {
  const status = deriveDisplayStatus(finding);
  const sla = slaStatus(finding);

  return (
    <li className="f-card">
      <div className="f-card__top">
        <Badge tone={priorityTone(finding.priority)}>
          {finding.priority ?? "—"}
        </Badge>
        <Badge tone={severityTone(finding.severity)}>
          {finding.severity.toUpperCase()}
        </Badge>
        <Link className="f-card__title" to={`/findings/${finding.finding_id}`}>
          {vulnLabel(finding.vulnerability_type)}
        </Link>
        <Badge tone={statusTone(status)}>{status}</Badge>
      </div>
      <div className="f-card__meta">
        <span>{finding.repository ?? "—"}</span>
        <span className="f-card__meta-file" title={finding.file}>
          {finding.file}
        </span>
        <Badge tone={sla.breached ? "danger" : "neutral"}>{sla.label}</Badge>
      </div>
      <details className="f-card__details">
        <summary className="f-card__summary">Details</summary>
        <div className="f-card__detail-rows">
          <div className="f-card__detail-row">
            <span className="f-card__detail-label">Source → Sink</span>
            <span className="f-card__detail-value">
              {finding.source_snippet || "—"} → {finding.sink_snippet || "—"}
            </span>
          </div>
          <div className="f-card__detail-row">
            <span className="f-card__detail-label">Confidence</span>
            <span className="f-card__detail-value">
              {formatConfidence(finding.validation_confidence)}
            </span>
          </div>
          {finding.sla.status === "active" &&
          finding.sla.remaining_seconds !== null ? (
            <div className="f-card__detail-row">
              <span className="f-card__detail-label">SLA</span>
              <span className="f-card__detail-value">
                {formatSlaRemaining(finding.sla.remaining_seconds)}
              </span>
            </div>
          ) : null}
        </div>
      </details>
    </li>
  );
}