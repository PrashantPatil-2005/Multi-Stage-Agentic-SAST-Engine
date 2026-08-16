import { useState } from "react";

import type { ApprovalListItem } from "../../api/approvals";
import type { FindingDetail } from "../../api/findingDetail";
import { useApprovalRequest } from "../../hooks/useApprovalRequest";
import { useApprovalReview } from "../../hooks/useApprovalReview";
import { ApprovalActions } from "../approvals/ApprovalActions";
import type { DecisionKind } from "../approvals/ApprovalActions";
import { ApprovalHistory } from "../approvals/ApprovalHistory";
import { ApprovalModal } from "../approvals/ApprovalModal";
import { approvalActionLabel } from "../approvals/approvalsHelpers";
import { vulnLabel } from "../findings/findingsHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { approvalStatusLabel, formatTimestamp } from "./detailHelpers";

function toApprovalListItem(
  detail: FindingDetail,
  approval: NonNullable<FindingDetail["approval"]>,
): ApprovalListItem {
  return {
    approval_id: approval.id,
    finding_id: approval.finding_id,
    status: approval.status,
    action: approval.action,
    version: approval.version,
    requested_by: approval.requested_by,
    requested_at: approval.requested_at,
    reviewed_by: approval.reviewed_by,
    reviewed_at: approval.reviewed_at,
    reason: approval.reason,
    vulnerability_type: detail.vulnerability_type,
    severity: detail.severity,
    priority: detail.risk?.priority ?? null,
    risk_score: detail.risk?.risk_score ?? null,
    repository: detail.repository,
    file: detail.source?.file ?? null,
  };
}

export function ApprovalPanel({
  detail,
  onApprovalChanged,
}: {
  detail: FindingDetail;
  onApprovalChanged: () => void;
}) {
  const approval = detail.approval;
  const review = useApprovalReview(
    approval ? toApprovalListItem(detail, approval) : null,
  );
  const request = useApprovalRequest();
  const [activeKind, setActiveKind] = useState<DecisionKind | null>(null);

  async function handleRequestApproval() {
    if (await request.requestApproval(detail.finding_id)) {
      onApprovalChanged();
    }
  }

  async function handleConfirm(reason: string) {
    if (!activeKind) return;
    const updated = await review.decide(activeKind, reason);
    if (updated) {
      setActiveKind(null);
      onApprovalChanged();
    }
  }

  const validation = detail.validation;
  const proof = detail.proof;

  return (
    <Card title="Human Approval">
      {!approval ? (
        <div className="fd-panel__body">
          <p className="fd-panel__empty">No approval request</p>
          {!validation ? (
            <p className="fd-approval__prereq">
              Finding has not been validated; approval requires VALIDATE verdict
              true_positive.
            </p>
          ) : validation.verdict !== "true_positive" ? (
            <p className="fd-approval__prereq">
              Finding is not eligible for approval: VALIDATE verdict is{" "}
              {validation.verdict} (requires true_positive)
            </p>
          ) : !proof ? (
            <p className="fd-approval__prereq">
              Finding has not been proven; approval requires PROVE status
              verified.
            </p>
          ) : proof.status !== "verified" ? (
            <p className="fd-approval__prereq">
              Finding is not eligible for approval: PROVE status is{" "}
              {proof.status} (requires verified)
            </p>
          ) : (
            <>
              {request.error ? (
                <p role="alert" className="fd-panel__error">
                  Unable to request approval: {request.error}
                </p>
              ) : null}
              <div className="fd-panel__actions">
                <Button
                  variant="secondary"
                  disabled={request.requesting}
                  onClick={handleRequestApproval}
                >
                  {request.requesting
                    ? "Requesting Approval\u2026"
                    : "Request Approval"}
                </Button>
              </div>
            </>
          )}
        </div>
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
            <span className="fd-panel__label">Approval ID</span>
            <span className="fd-panel__value fd-panel__mono">{approval.id}</span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Action</span>
            <span className="fd-panel__value">
              {approvalActionLabel(approval.action)}
            </span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Review Cycle</span>
            <span className="fd-panel__value">{approval.version}</span>
          </div>
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
          <div className="fd-approval__actions">
            <ApprovalActions
              status={approval.status}
              submitting={review.submitting}
              onAction={setActiveKind}
            />
          </div>
          {review.success ? (
            <p role="status" aria-live="polite" className="fd-approval__available">
              {review.success}
            </p>
          ) : null}
          {review.error && !activeKind ? (
            <p role="alert" className="fd-panel__error">
              {review.error}
            </p>
          ) : null}
          <ApprovalHistory events={review.history} loading={review.loading} />
          {activeKind ? (
            <ApprovalModal
              kind={activeKind}
              findingLabel={vulnLabel(detail.vulnerability_type)}
              action={approval.action}
              priority={detail.risk?.priority ?? null}
              submitting={review.submitting}
              error={review.error}
              onConfirm={handleConfirm}
              onClose={() => {
                review.clearFeedback();
                setActiveKind(null);
              }}
            />
          ) : null}
        </div>
      )}
    </Card>
  );
}