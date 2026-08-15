import { useCallback, useEffect, useState } from "react";

import { getValidationSummary } from "../api/validation";
import type { ValidationSummary } from "../api/validation";

export interface ValidationState {
  summary: ValidationSummary | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useValidation(): ValidationState {
  const [summary, setSummary] = useState<ValidationSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getValidationSummary()
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
