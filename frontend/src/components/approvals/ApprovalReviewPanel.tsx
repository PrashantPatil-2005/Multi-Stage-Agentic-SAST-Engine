import { useState } from "react";
import { Link } from "react-router-dom";

import type { ApprovalListItem, ApprovalStatus } from "../../api/approvals";
import { useApprovalReview } from "../../hooks/useApprovalReview";
import type { FindingDetail } from "../../api/findingDetail";
import { formatConfidence, vulnLabel } from "../findings/findingsHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { RiskPanel } from "../finding-detail/RiskPanel";
import { ValidationPanel } from "../finding-detail/ValidationPanel";
import { ProofPanel } from "../finding-detail/ProofPanel";
import { SlaPanel } from "../finding-detail/SlaPanel";
import { formatTimestamp } from "../finding-detail/detailHelpers";
import { ApprovalActions } from "./ApprovalActions";
import type { DecisionKind } from "./ApprovalActions";
import { ApprovalHistory, PendingReviewBadge } from "./ApprovalHistory";
import { ApprovalModal } from "./ApprovalModal";
import { ApprovalStatusBadge } from "./ApprovalStatusBadge";
import { approvalActionLabel, shortFindingId } from "./approvalsHelpers";

export interface ApprovalReviewPanelProps {
  approval: ApprovalListItem | null;
  onStatusChanged: () => void;
}

function FindingCard({
  finding,
}: {
  finding: FindingDetail;
}) {
  return (
    <Card title="Finding">
      <dl className="ap-kv">
        <div className="ap-kv__row">
          <dt>Finding ID</dt>
          <dd className="ap-kv__mono" title={finding.finding_id}>
            {shortFindingId(finding.finding_id)}
          </dd>
        </div>
        <div className="ap-kv__row">
          <dt>Vulnerability</dt>
          <dd>{vulnLabel(finding.vulnerability_type)}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Severity</dt>
          <dd>{finding.severity.toUpperCase()}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Confidence</dt>
          <dd>{formatConfidence(finding.scanner_confidence)}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Repository</dt>
          <dd>{finding.repository ?? "\u2014"}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>File</dt>
          <dd className="ap-kv__mono">{finding.source.file}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Source</dt>
          <dd className="ap-kv__mono">
            {finding.source.file}:{finding.source.line}
          </dd>
        </div>
        <div className="ap-kv__row">
          <dt>Sink</dt>
          <dd className="ap-kv__mono">
            {finding.sink.file}:{finding.sink.line}
          </dd>
        </div>
      </dl>
    </Card>
  );
}

function ApprovalRequestCard({
  status,
  action,
  version,
  requestedBy,
  requestedAt,
  reviewedBy,
  reviewedAt,
  reason,
}: {
  status: string;
  action: string;
  version: number;
  requestedBy: string;
  requestedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  reason: string | null;
}) {
  return (
    <Card title="Approval Request">
      <dl className="ap-kv">
        <div className="ap-kv__row">
          <dt>Status</dt>
          <dd>
            <ApprovalStatusBadge status={status as ApprovalStatus} />
          </dd>
        </div>
        <div className="ap-kv__row">
          <dt>Action</dt>
          <dd>{approvalActionLabel(action)}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Review Cycle</dt>
          <dd>Cycle {version}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Requested By</dt>
          <dd>{requestedBy}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Requested At</dt>
          <dd className="ap-kv__mono">{formatTimestamp(requestedAt)}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Reviewed By</dt>
          <dd>{reviewedBy ?? "\u2014"}</dd>
        </div>
        <div className="ap-kv__row">
          <dt>Reviewed At</dt>
          <dd className="ap-kv__mono">
            {reviewedAt ? formatTimestamp(reviewedAt) : "\u2014"}
          </dd>
        </div>
        <div className="ap-kv__row">
          <dt>Reason</dt>
          <dd>{reason?.trim() ? reason : "\u2014"}</dd>
        </div>
      </dl>
    </Card>
  );
}

export function ApprovalReviewPanel({
  approval,
  onStatusChanged,
}: ApprovalReviewPanelProps) {
  const {
    request,
    finding,
    history,
    loading,
    failed,
    submitting,
    error,
    success,
    decide,
    refreshHistory,
    clearFeedback,
  } = useApprovalReview(approval);
  const [activeKind, setActiveKind] = useState<DecisionKind | null>(null);

  async function handleConfirm(reason: string) {
    if (!activeKind) return;
    const updated = await decide(activeKind, reason);
    if (updated) {
      setActiveKind(null);
      onStatusChanged();
    }
  }

  if (!approval) {
    return (
      <Card title="Approval Review">
        <p className="ap-review__empty">
          Select an approval request from the queue to review it.
        </p>
      </Card>
    );
  }

  return (
    <Card title="Approval Review" className="ap-review">
      {loading ? (
        <div className="ap-skeleton" aria-hidden="true">
          <div className="ap-skeleton__line ap-skeleton__line--wide" />
          <div className="ap-skeleton__line" />
          <div className="ap-skeleton__line" />
          <div className="ap-skeleton__line" />
        </div>
      ) : failed ? (
        <div className="ap-review__failed">
          <p>Unable to load the approval details.</p>
          <Button variant="secondary" size="sm" onClick={refreshHistory}>
            Retry
          </Button>
        </div>
      ) : request && finding ? (
        <>
          <div className="ap-review__header">
            <div className="ap-review__heading">
              <h3 className="ap-review__vuln">
                {vulnLabel(finding.vulnerability_type)}
              </h3>
              <div className="ap-review__badges">
                <ApprovalStatusBadge status={request.status} />
                {request.status === "pending" ? <PendingReviewBadge /> : null}
                <Badge tone="info">Cycle {request.version}</Badge>
              </div>
            </div>
            <Link
              className="ap-review__detail-link"
              to={`/findings/${finding.finding_id}`}
            >
              View finding detail
            </Link>
          </div>

          <div className="ap-review__sections">
            <FindingCard finding={finding} />
            <ApprovalRequestCard
              status={request.status}
              action={request.action}
              version={request.version}
              requestedBy={request.requested_by}
              requestedAt={request.requested_at}
              reviewedBy={request.reviewed_by}
              reviewedAt={request.reviewed_at}
              reason={request.reason}
            />
            <RiskPanel detail={finding} />
            <ValidationPanel detail={finding} />
            <ProofPanel detail={finding} />
            <SlaPanel detail={finding} />
          </div>

          <ApprovalActions
            status={request.status}
            submitting={submitting}
            onAction={setActiveKind}
          />

          {success ? (
            <p
              className="ap-feedback ap-feedback--success"
              role="status"
              aria-live="polite"
            >
              {success}
            </p>
          ) : null}
          {error && !activeKind ? (
            <p role="alert" className="ap-feedback ap-feedback--error">
              {error}
            </p>
          ) : null}

          <ApprovalHistory events={history} loading={loading} />

          {activeKind ? (
            <ApprovalModal
              kind={activeKind}
              findingLabel={vulnLabel(finding.vulnerability_type)}
              action={request.action}
              priority={finding.risk?.priority ?? null}
              submitting={submitting}
              error={error}
              onConfirm={handleConfirm}
              onClose={() => {
                clearFeedback();
                setActiveKind(null);
              }}
            />
          ) : null}
        </>
      ) : (
        <p className="ap-review__empty">
          Approval details unavailable for this request.
        </p>
      )}
    </Card>
  );
}
