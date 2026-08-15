/* Typed API client for the repositories summary. Mirrors the backend
   response models in app/api/repositories_models.py (GET /api/repositories). */

import { fetchJson } from "./dashboard";

export interface RepositoryFindings {
  total: number;
  by_priority: Record<string, number>;
  highest_priority: string | null;
}

export interface RepositoryRisk {
  available: boolean;
  highest_risk_score: number | null;
  highest_priority: string | null;
  top_finding_id: string | null;
}

export interface RepositoryValidation {
  available: boolean;
  true_positive: number;
  false_positive: number;
  uncertain: number;
}

export interface RepositoryProof {
  available: boolean;
  verified: number;
  not_verified: number;
  blocked: number;
  error: number;
}

export interface RepositorySla {
  available: boolean;
  active: number;
  breached: number;
  resolved: number;
}

export interface RepositorySummary {
  project_id: string;
  name: string;
  source_type: string;
  language: string;
  status: string;
  location: string;
  created_at: string;
  findings: RepositoryFindings | null;
  risk: RepositoryRisk | null;
  validation: RepositoryValidation | null;
  proof: RepositoryProof | null;
  sla: RepositorySla | null;
}

export interface RepositoryList {
  has_repositories: boolean;
  repositories: RepositorySummary[];
}

export function getRepositories(): Promise<RepositoryList> {
  return fetchJson<RepositoryList>("/api/repositories");
}
