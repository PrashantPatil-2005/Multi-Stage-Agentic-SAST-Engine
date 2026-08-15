import { useCallback, useEffect, useState } from "react";

import { getApprovals } from "../api/approvals";
import type { ApprovalListItem } from "../api/approvals";

export interface ApprovalsState {
  items: ApprovalListItem[];
  loading: boolean;
  failed: boolean;
  reload: () => void;
}

export function useApprovals(): ApprovalsState {
  const [items, setItems] = useState<ApprovalListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    getApprovals()
      .then((data) => {
        if (cancelled) return;
        setItems(data);
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
  }, [attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { items, loading, failed, reload };
}
