import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { approvalStatusLabel, formatTimestamp } from "./detailHelpers";

export function ApprovalPanel({ detail }: { detail: FindingDetail }) {
  const approval = detail.approval;

  return (
    <Card title="Human Approval">
      {!approval ? (
        <p className="fd-panel__empty">No approval request</p>
      ) : (
        <div className="fd-panel__body">
          <div className="fd-panel__line">
            <span className="fd-panel__label">Approval State</span>
            <Badge
              tone={
                approval.status === "approved"
                  ? "success"
                  : approval.status === "rejected"
                    ? "danger"
                    : "warning"
              }
            >
              {approvalStatusLabel(approval.status)}
            </Badge>
          </div>
          {approval.status === "pending" ||
          approval.status === "changes_requested" ? (
            <p className="fd-approval__required">Approval required</p>
          ) : null}
          <div className="fd-panel__line">
            <span className="fd-panel__label">Requested By</span>
            <span className="fd-panel__value">{approval.requested_by || "—"}</span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Requested At</span>
            <span className="fd-panel__value fd-panel__mono">
              {formatTimestamp(approval.requested_at)}
            </span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Reviewed By</span>
            <span className="fd-panel__value">{approval.reviewed_by || "—"}</span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Reviewed At</span>
            <span className="fd-panel__value fd-panel__mono">
              {formatTimestamp(approval.reviewed_at)}
            </span>
          </div>
          {approval.reason ? (
            <div className="fd-panel__line fd-panel__line--top">
              <span className="fd-panel__label">Reason</span>
              <p className="fd-panel__reason">{approval.reason}</p>
            </div>
          ) : null}
        </div>
      )}
    </Card>
  );
}
