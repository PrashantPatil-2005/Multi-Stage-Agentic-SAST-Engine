import { APPROVAL_STATUS_LABEL } from "../../api/approvals";
import type { ApprovalStatus } from "../../api/approvals";
import { Badge } from "../ui/Badge";

export interface ApprovalHistoryEvent {
  id: string;
  previous_status: string | null;
  new_status: string;
  actor: string;
  reason: string | null;
  created_at: string;
}

function statusLabel(status: string): string {
  return APPROVAL_STATUS_LABEL[status as ApprovalStatus] ?? status;
}

function eventTransition(event: ApprovalHistoryEvent): string {
  if (event.previous_status === null) {
    return `Request created \u2192 ${statusLabel(event.new_status)}`;
  }
  return `${statusLabel(event.previous_status)} \u2192 ${statusLabel(
    event.new_status,
  )}`;
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export function ApprovalHistory({
  events,
  loading,
}: {
  events: ApprovalHistoryEvent[];
  loading: boolean;
}) {
  return (
    <div className="ap-history">
      <h4 className="ap-history__title">Audit History</h4>
      {loading ? (
        <p className="ap-history__empty">{"Loading history\u2026"}</p>
      ) : events.length === 0 ? (
        <p className="ap-history__empty">No history recorded.</p>
      ) : (
        <ol aria-label="Approval history" className="ap-history__list">
          {events.map((event) => (
            <li key={event.id} className="ap-history__item">
              <div className="ap-history__transition">
                {eventTransition(event)}
              </div>
              <div className="ap-history__meta">
                <span className="ap-history__actor">{event.actor}</span>
                <span className="ap-history__time">
                  {formatTimestamp(event.created_at)}
                </span>
              </div>
              {event.reason?.trim() ? (
                <p className="ap-history__reason">{event.reason}</p>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

export function PendingReviewBadge() {
  return <Badge tone="warning">PENDING REVIEW</Badge>;
}
