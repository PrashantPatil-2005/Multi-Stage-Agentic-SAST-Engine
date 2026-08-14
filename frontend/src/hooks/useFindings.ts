import { useCallback, useEffect, useState } from "react";

import { getFindings } from "../api/findings";
import type { FindingListItem } from "../api/findings";

export interface FindingsState {
  findings: FindingListItem[];
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useFindings(): FindingsState {
  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getFindings()
      .then((data) => {
        if (cancelled) return;
        setFindings(data);
        setLoading(false);
      })
      .catch(() => {
        if (cancelled) return;
        setError(true);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { findings, loading, error, reload };
}