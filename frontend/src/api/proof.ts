/* Typed API client for the Proof page. Mirrors the backend response models
   in app/api/proof_models.py. All data is read-only; the backend is the
   source of truth for proof status, summary and duration. Nothing here
   executes a proof and no payloads or raw commands are ever displayed. */

import { fetchJson } from "./dashboard";

export interface ProofKpi {
  available: boolean;
  value: number;
}

export interface ProofKpis {
  total: ProofKpi;
  verified: ProofKpi;
  not_verified: ProofKpi;
  blocked: ProofKpi;
  errors: ProofKpi;
}

export interface SandboxPolicyInfo {
  network_enabled: boolean;
  allow_loopback: boolean;
  timeout_seconds: number;
  max_output_bytes: number;
  max_processes: number;
}

export interface ProofRow {
  finding_id: string;
  vulnerability_type: string | null;
  severity: string | null;
  priority: string | null; // from the stored risk assessment, when present
  validation: string | null; // stored verdict, when present
  status: string; // verified / not_verified / blocked / error
  confidence: number;
  duration_ms: number;
  created_at: string;
  summary: string | null;
  error: string | null;
  repository: string | null;
  file: string | null;
  sandbox_policy: SandboxPolicyInfo | null;
}

export interface ProofSummary {
  has_findings: boolean;
  kpis: ProofKpis;
  records: ProofRow[];
}

export function getProofSummary(): Promise<ProofSummary> {
  return fetchJson<ProofSummary>("/api/proof");
}
