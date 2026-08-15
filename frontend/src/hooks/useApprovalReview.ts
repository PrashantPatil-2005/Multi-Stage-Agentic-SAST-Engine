import { useCallback, useEffect, useRef, useState } from "react";

import {
  getApprovalForFinding,
  getApprovalHistory,
  REVIEWER,
  submitApprovalDecision,
} from "../api/approvals";
import type {
  ApprovalDecisionKind,
  ApprovalEvent,
  ApprovalListItem,
  ApprovalRequest,
} from "../api/approvals";
import { getFindingDetail } from "../api/findingDetail";
import type { FindingDetail } from "../api/findingDetail";

export interface ApprovalReviewState {
  request: ApprovalRequest | null;
  finding: FindingDetail | null;
  history: ApprovalEvent[];
  loading: boolean;
  failed: boolean;
  submitting: boolean;
  error: string | null;
  success: string | null;
  refreshHistory: () => void;
  decide: (kind: ApprovalDecisionKind, reason: string) => Promise<ApprovalRequest | null>;
  clearFeedback: () => void;
}

/**
 * Loads everything the review panel needs for one approval request:
 * the request itself, the finding detail (risk/validation/proof/SLA
 * context) and the audit history. Decisions are submitted through the
 * backend approval workflow and never bypass it.
 */
export function useApprovalReview(
  approval: ApprovalListItem | null,
): ApprovalReviewState {
  const [request, setRequest] = useState<ApprovalRequest | null>(null);
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [history, setHistory] = useState<ApprovalEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);

  const approvalId = approval?.approval_id;
  const findingId = approval?.finding_id;

  const previousSelectionRef = useRef<string | null>(null);

  useEffect(() => {
    const selectionKey = `${approvalId ?? ""}/${findingId ?? ""}`;
    const isNewSelection = previousSelectionRef.current !== selectionKey;
    previousSelectionRef.current = selectionKey;
    if (!approvalId || !findingId) {
      setRequest(null);
      setFinding(null);
      setHistory([]);
      setLoading(false);
      setFailed(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    if (isNewSelection) {
      setError(null);
      setSuccess(null);
    }
    Promise.all([
      getApprovalForFinding(findingId),
      getFindingDetail(findingId),
      getApprovalHistory(approvalId),
    ])
      .then(([requestData, findingData, historyData]) => {
        if (cancelled) return;
        setRequest(requestData);
        setFinding(findingData);
        setHistory(historyData);
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setFailed(true);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [approvalId, findingId, historyRefresh]);

  const refreshHistory = useCallback(
    () => setHistoryRefresh((n) => n + 1),
    [],
  );

  const decide = useCallback(
    async (kind: ApprovalDecisionKind, reason: string): Promise<ApprovalRequest | null> => {
      if (!approvalId) return null;
      setSubmitting(true);
      setError(null);
      setSuccess(null);
      try {
        const updated = await submitApprovalDecision(approvalId, kind, {
          reviewed_by: REVIEWER,
          reason,
        });
        setRequest(updated);
        setSuccess("Approval recorded successfully.");
        setHistoryRefresh((n) => n + 1);
        return updated;
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : "Approval update failed.";
        setError(message);
        return null;
      } finally {
        setSubmitting(false);
      }
    },
    [approvalId],
  );

  const clearFeedback = useCallback(() => {
    setError(null);
    setSuccess(null);
  }, []);

  return {
    request,
    finding,
    history,
    loading,
    failed,
    submitting,
    error,
    success,
    refreshHistory,
    decide,
    clearFeedback,
  };
}
