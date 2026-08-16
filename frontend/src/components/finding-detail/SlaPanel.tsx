import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { formatSlaRemaining } from "../findings/findingsHelpers";
import {
  formatEscalationLevel,
  formatTimestamp,
  slaStatusLabel,
} from "./detailHelpers";

export function SlaPanel({
  detail,
  onStartSla,
  slaLoading = false,
  slaError = null,
  onCheckSla,
  checking = false,
  checkError = null,
  disabled = false,
}: {
  detail: FindingDetail;
  onStartSla?: () => void;
  slaLoading?: boolean;
  slaError?: string | null;
  onCheckSla?: () => void;
  checking?: boolean;
  checkError?: string | null;
  /** Disable the actions until a scan-run context is selected (Phase 14J). */
  disabled?: boolean;
}) {
  const sla = detail.sla;
  const risk = detail.risk;
  const interactive = typeof onStartSla === "function" || typeof onCheckSla === "function";

  if (!sla) {
    return (
      <Card title="SLA">
        <div className="fd-panel__body">
          <p className="fd-panel__empty">No SLA</p>
          {!risk ? (
            <p className="fd-sla__prereq">
              Assess risk before starting an SLA.
            </p>
          ) : interactive ? (
            <>
              {slaError ? (
                <p className="fd-panel__error" role="alert">
                  Unable to start SLA: {slaError}
                </p>
              ) : null}
              <div className="fd-panel__actions">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={slaLoading || disabled}
                  onClick={onStartSla}
                >
                  {slaLoading ? "Starting SLA\u2026" : "Start SLA"}
                </Button>
              </div>
            </>
          ) : null}
        </div>
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
        {interactive && checkError ? (
          <p className="fd-panel__error" role="alert">
            Unable to check SLA: {checkError}
          </p>
        ) : null}
        {interactive ? (
          <div className="fd-panel__actions">
            <Button
              size="sm"
              variant="secondary"
              disabled={checking || disabled}
              onClick={onCheckSla}
            >
              {checking ? "Checking SLA\u2026" : "Check SLA"}
            </Button>
          </div>
        ) : null}
      </div>
    </Card>
  );
}