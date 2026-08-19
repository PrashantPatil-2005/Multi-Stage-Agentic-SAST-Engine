/* Typed API client for the dashboard. Mirrors the backend response models
   in app/api/dashboard_models.py. */

export interface ProjectRef {
  id: string;
  name: string;
}

export interface DashboardKpi {
  available: boolean;
  value: number;
}

export interface DashboardPipelineStage {
  stage: string;
  count: number | null;
  count_label: string | null;
  description: string;
}

export interface DashboardFinding {
  finding_id: string;
  priority: string | null;
  vulnerability_type: string;
  repository: string | null;
  file: string;
  status: string;
  risk_score: number | null;
}

export interface DashboardSlaSummary {
  available: boolean;
  active: number;
  breached: number;
  highest_priority_breach: string | null;
  escalation_count: number;
}

export interface DashboardVerification {
  available: boolean;
  true_positive: number;
  false_positive: number;
  uncertain: number;
  verified: number;
  not_verified: number;
  blocked: number;
  errors: number;
}

export interface DashboardActivityItem {
  kind: string;
  finding_id: string | null;
  message: string;
  created_at: string;
}

export interface DashboardSummary {
  projects: ProjectRef[];
  kpis: Record<string, DashboardKpi>;
  pipeline: DashboardPipelineStage[];
  critical_findings: DashboardFinding[];
  sla: DashboardSlaSummary;
  verification: DashboardVerification;
  recent_activity: DashboardActivityItem[];
}

export async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { credentials: "include" });
  if (!response.ok) {
    throw new Error(`request failed: ${path} (${response.status})`);
  }
  return (await response.json()) as T;
}

export function getDashboardSummary(projectId?: string): Promise<DashboardSummary> {
  const params = new URLSearchParams();
  if (projectId) params.set("project_id", projectId);
  const qs = params.toString();
  return fetchJson<DashboardSummary>(`/api/dashboard/summary${qs ? `?${qs}` : ""}`);
}

export function getProjects(): Promise<ProjectRef[]> {
  return fetchJson<ProjectRef[]>("/api/projects");
}