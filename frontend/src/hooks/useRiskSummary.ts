import { useCallback, useEffect, useState } from "react";

import { getRiskSummary } from "../api/risk";
import type { RiskSummary } from "../api/risk";

export interface RiskState {
  summary: RiskSummary | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useRiskSummary(): RiskState {
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getRiskSummary()
      .then((data) => {
        if (cancelled) return;
        setSummary(data);
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

  return { summary, loading, error, reload };
}
