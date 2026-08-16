import { useState } from "react";

import { createApprovalRequest } from "../api/approvals";

export interface ApprovalRequestState {
  requesting: boolean;
  error: string | null;
  requestApproval: (findingId: string) => Promise<boolean>;
}

/**
 * Submits approval requests through the backend approval workflow.
 * The returned boolean reports success so the caller can refetch the
 * finding detail as the new backend state.
 */
export function useApprovalRequest(): ApprovalRequestState {
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function requestApproval(findingId: string): Promise<boolean> {
    setRequesting(true);
    setError(null);
    try {
      await createApprovalRequest(findingId);
      return true;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Approval request failed.";
      setError(message);
      return false;
    } finally {
      setRequesting(false);
    }
  }

  return { requesting, error, requestApproval };
}