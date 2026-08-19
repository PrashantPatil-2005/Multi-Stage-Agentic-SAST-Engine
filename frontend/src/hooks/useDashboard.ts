import { useCallback, useEffect, useState } from "react";

import { getDashboardSummary, getProjects } from "../api/dashboard";
import type { DashboardSummary, ProjectRef } from "../api/dashboard";

export interface DashboardState {
  summary: DashboardSummary | null;
  projects: ProjectRef[];
  loading: boolean;
  error: boolean;
  reload: () => void;
}

export function useDashboard(projectId?: string): DashboardState {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [projects, setProjects] = useState<ProjectRef[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    Promise.all([getDashboardSummary(projectId), getProjects()])
      .then(([summaryData, projectData]) => {
        if (cancelled) return;
        setSummary(summaryData);
        setProjects(projectData);
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
  }, [attempt, projectId]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { summary, projects, loading, error, reload };
}