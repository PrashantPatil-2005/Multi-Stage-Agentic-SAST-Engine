import { useCallback, useEffect, useState } from "react";

import { getAllScans } from "../api/scans";
import type { ScanRun } from "../api/scans";

export interface RecentScansState {
  runs: ScanRun[] | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

/** Loads the newest scan runs across projects (read-only). */
export function useRecentScans(limit = 5): RecentScansState {
  const [runs, setRuns] = useState<ScanRun[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getAllScans(limit)
      .then((data) => {
        if (cancelled) return;
        if (!Array.isArray(data)) {
          throw new Error("unexpected scan list response");
        }
        setRuns(data);
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
  }, [limit, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { runs, loading, error, reload };
}
