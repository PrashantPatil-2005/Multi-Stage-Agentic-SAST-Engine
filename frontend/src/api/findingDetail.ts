/* Typed API client for the finding detail view.
   Mirrors the backend response model in app/api/findings_models.py
   (GET /api/findings/{finding_id}). Read-only: nothing here mutates state. */

import type { ApprovalRequest } from "./approvals";
import type { RemediationRecord } from "./remediation";
import type { ScanRun } from "./scans";

export interface FindingDetailSource {
  file: string;
  line: number;
  snippet: string;
  kind: string;
}

export interface FindingDetailSink {
  file: string;
  line: number;
  snippet: string;
  kind: string;
}

export interface FindingDetailTaintStep {
  file: string;
  line: number;
  snippet: string;
  step_type:
    | "source"
    | "assignment"
    | "propagation"
    | "string_construction"
    | "sink";
}

export interface RiskFactor {
  name: string;
  value: string;
  points: number;
  description: string;
}

export interface RiskAssessment {
  finding_id: string;
  vulnerability_type: string;
  severity: string;
  risk_score: number;
  priority: string;
  factors: RiskFactor[];
  assessed_at: string;
  related_finding_ids: string[];
}

export interface FindingSlaDetail {
  status: "active" | "breached" | "resolved" | "not_applicable";
  priority: string | null;
  started_at: string | null;
  due_at: string | null;
  breached_at: string | null;
  resolved_at: string | null;
  escalation_level: number;
  remaining_seconds: number | null;
}

export interface ValidationResult {
  finding_id: string;
  verdict: string;
  confidence: number;
  reasoning: string;
  evidence_used: string[];
  missing_evidence: string[];
  recommended_next_step: string;
  model: string | null;
  validated_at: string;
}

export interface SandboxPolicy {
  network_enabled: boolean;
  allow_loopback: boolean;
  allowed_paths: string[];
  timeout_seconds: number;
  max_output_bytes: number;
  max_processes: number;
  temporary_directory: string;
}

export interface FindingProofDetail {
  status: "verified" | "not_verified" | "blocked" | "error";
  confidence: number;
  summary: string;
  created_at: string;
  duration_ms: number;
  error: string | null;
  sandbox_policy: SandboxPolicy | null;
}

export interface FindingDedupDetail {
  fingerprint: string;
  structural_signature: string;
  is_canonical: boolean;
  canonical_finding_id: string;
  occurrence_count: number;
  related_finding_ids: string[];
}

/** Authoritative repository that owns a finding (from backend lineage). */
export interface FindingProject {
  project_id: string;
  name: string;
  source_type: string;
  location: string;
  language: string;
}

export interface FindingDetail {
  finding_id: string;
  vulnerability_type: string;
  severity: string;
  scanner_confidence: number;
  status: string;
  repository: string | null;
  source: FindingDetailSource;
  sink: FindingDetailSink;
  taint_path: FindingDetailTaintStep[];
  risk: RiskAssessment | null;
  sla: FindingSlaDetail | null;
  validation: ValidationResult | null;
  proof: FindingProofDetail | null;
  approval: ApprovalRequest | null;
  dedup: FindingDedupDetail | null;
  /** Post-approval remediation workflow record for this finding. */
  remediation?: RemediationRecord | null;
  /** Owning project + every producing scan run (explicit lineage). */
  project?: FindingProject | null;
  scan_runs?: ScanRun[];
}

export class FindingApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "FindingApiError";
  }
}

export function isNotFoundError(error: unknown): boolean {
  return error instanceof FindingApiError && error.status === 404;
}

export async function getFindingDetail(findingId: string): Promise<FindingDetail> {
  const response = await fetch(
    `/api/findings/${encodeURIComponent(findingId)}`,
  );
  if (response.status === 404) {
    throw new FindingApiError(404, `finding not found: ${findingId}`);
  }
  if (!response.ok) {
    throw new FindingApiError(
      response.status,
      `request failed: /api/findings/${findingId} (${response.status})`,
    );
  }
  return (await response.json()) as FindingDetail;
}
