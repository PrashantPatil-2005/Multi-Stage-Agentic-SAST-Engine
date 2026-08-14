/* Typed API client for findings. Mirrors the backend response models in
   app/api/findings_models.py (GET /api/findings). */

import { fetchJson } from "./dashboard";

export interface FindingSlaInfo {
  status: "active" | "breached" | "resolved" | "not_applicable" | "none";
  remaining_seconds: number | null;
  priority: string | null;
}

export interface FindingListItem {
  finding_id: string;
  vulnerability_type: string;
  severity: string;
  scanner_confidence: number;
  priority: string | null;
  risk_score: number | null;
  repository: string | null;
  file: string;
  source_snippet: string;
  sink_snippet: string;
  source_kind: string;
  sink_kind: string;
  verdict: string | null;
  validation_confidence: number | null;
  validated_at: string | null;
  proof_status: string | null;
  approval_status: string | null;
  sla: FindingSlaInfo;
}

export function getFindings(): Promise<FindingListItem[]> {
  return fetchJson<FindingListItem[]>("/api/findings");
}