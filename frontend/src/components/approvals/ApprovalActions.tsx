import { Button } from "../ui/Button";

export type DecisionKind = "approve" | "reject" | "request-changes" | "resubmit";

export interface ApprovalActionsProps {
  status: string;
  submitting: boolean;
  onAction: (kind: DecisionKind) => void;
}

export function ApprovalActions({
  status,
  submitting,
  onAction,
}: ApprovalActionsProps) {
  if (status === "approved" || status === "rejected") {
    return (
      <p className="ap-actions__terminal">
        {status === "approved"
          ? "Approved \u2014 action authorized."
          : "Rejected \u2014 no further action."}
      </p>
    );
  }

  if (status === "changes_requested") {
    return (
      <div className="ap-actions">
        <p className="ap-actions__note">
          Additional review required. Resubmit once the requested changes are
          in place to start a new review cycle.
        </p>
        <div className="ap-actions__row">
          <Button
            variant="primary"
            disabled={submitting}
            onClick={() => onAction("resubmit")}
          >
            Resubmit for Review
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="ap-actions">
      <div className="ap-actions__row">
        <Button
          variant="primary"
          disabled={submitting}
          onClick={() => onAction("approve")}
        >
          Approve
        </Button>
        <Button
          variant="danger"
          disabled={submitting}
          onClick={() => onAction("reject")}
        >
          Reject
        </Button>
        <Button
          variant="secondary"
          disabled={submitting}
          onClick={() => onAction("request-changes")}
        >
          Request Changes
        </Button>
      </div>
    </div>
  );
}
