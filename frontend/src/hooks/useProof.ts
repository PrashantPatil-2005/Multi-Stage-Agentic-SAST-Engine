import { useCallback, useEffect, useState } from "react";

import { getProofSummary } from "../api/proof";
import type { ProofSummary } from "../api/proof";

export interface ProofState {
  summary: ProofSummary | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useProof(): ProofState {
  const [summary, setSummary] = useState<ProofSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getProofSummary()
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
