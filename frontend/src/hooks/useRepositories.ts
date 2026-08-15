import { useCallback, useEffect, useState } from "react";

import { getRepositories } from "../api/repositories";
import type { RepositoryList } from "../api/repositories";

export interface RepositoriesState {
  list: RepositoryList | null;
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useRepositories(): RepositoriesState {
  const [list, setList] = useState<RepositoryList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    getRepositories()
      .then((data) => {
        if (cancelled) return;
        setList(data);
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

  return { list, loading, error, reload };
}
