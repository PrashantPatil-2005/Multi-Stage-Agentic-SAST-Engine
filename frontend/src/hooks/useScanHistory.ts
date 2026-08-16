import { useCallback, useEffect, useState } from "react";

import { getProjectScans } from "../api/scans";
import type { ScanRun } from "../api/scans";

export interface ScanHistoryState {
  runs: ScanRun[] | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useScanHistory(projectId: string): ScanHistoryState {
  const [runs, setRuns] = useState<ScanRun[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getProjectScans(projectId)
      .then((data) => {
        if (cancelled) return;
        setRuns(data);
      })
      .catch(() => {
        if (cancelled) return;
        setError(true);
        setRuns(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { runs, loading, error, reload };
}