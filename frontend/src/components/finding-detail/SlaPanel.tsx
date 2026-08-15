import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { formatSlaRemaining } from "../findings/findingsHelpers";
import {
  formatEscalationLevel,
  formatTimestamp,
  slaStatusLabel,
} from "./detailHelpers";

export function SlaPanel({ detail }: { detail: FindingDetail }) {
  const sla = detail.sla;

  if (!sla) {
    return (
      <Card title="SLA">
        <p className="fd-panel__empty">No SLA</p>
      </Card>
    );
  }

  const breached = sla.status === "breached";

  return (
    <Card title="SLA">
      <div className="fd-panel__body">
        <div className="fd-panel__line">
          <span className="fd-panel__label">SLA Status</span>
          <Badge tone={breached ? "danger" : sla.status === "active" ? "warning" : "success"}>
            {slaStatusLabel(sla.status)}
          </Badge>
        </div>
        {breached ? (
          <p className="fd-sla__breach" role="alert">
            SLA BREACHED
          </p>
        ) : null}
        <div className="fd-panel__line">
          <span className="fd-panel__label">Priority</span>
          <span className="fd-panel__value">{sla.priority ?? "—"}</span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Started</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatTimestamp(sla.started_at)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Due</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatTimestamp(sla.due_at)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Breached At</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatTimestamp(sla.breached_at)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Escalation Level</span>
          <span className="fd-panel__value">{formatEscalationLevel(sla.escalation_level)}</span>
        </div>
        {sla.status === "active" && sla.remaining_seconds !== null ? (
          <p className="fd-sla__remaining">
            {formatSlaRemaining(sla.remaining_seconds)}
          </p>
        ) : null}
      </div>
    </Card>
  );
}
