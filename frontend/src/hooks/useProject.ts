import { useCallback, useEffect, useState } from "react";

import { getProjectDetail } from "../api/projects";
import type { ProjectDetail } from "../api/projects";

export interface ProjectState {
  project: ProjectDetail | null;
  loading: boolean;
  error: boolean;
  notFound: boolean;
  reload: () => void;
}

/** Loads one project by id (404 -> ``notFound``; never falls back). */
export function useProject(projectId: string | undefined): ProjectState {
  const [project, setProject] = useState<ProjectDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!projectId) {
      setProject(null);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(false);
    setNotFound(false);
    getProjectDetail(projectId)
      .then((data) => {
        if (cancelled) return;
        setProject(data);
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        if (
          reason instanceof Error &&
          "status" in reason &&
          (reason as { status: number }).status === 404
        ) {
          setNotFound(true);
        } else {
          setError(true);
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [projectId, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { project, loading, error, notFound, reload };
}
