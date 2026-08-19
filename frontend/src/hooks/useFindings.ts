import { useCallback, useEffect, useState } from "react";

import { FindingsRequestError, getFindings } from "../api/findings";
import type { FindingListItem } from "../api/findings";

export interface FindingsState {
  findings: FindingListItem[];
  loading: boolean;
  error: boolean;
  notFound: boolean;
  reload: () => void;
}

/** Loads findings, optionally scoped to one repository (project id) and/or
    filtered by a search query. When scoped and the project does not exist,
    ``notFound`` is set instead of silently falling back to the global list. */
export function useFindings(projectId?: string, search?: string): FindingsState {
  const [findings, setFindings] = useState<FindingListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    setNotFound(false);
    getFindings(projectId, search)
      .then((data) => {
        if (cancelled) return;
        setFindings(data);
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        if (reason instanceof FindingsRequestError && reason.status === 404) {
          setNotFound(true);
        } else {
          setError(true);
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, search, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { findings, loading, error, notFound, reload };
}
