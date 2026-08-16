/* Typed API client for finding deduplication. Mirrors the backend contracts
   in app/api/routes/dedup.py and app/dedup/models.py
   (POST /api/deduplicate). */

import { requestJson } from "./projects";

export interface DeduplicationGroup {
  fingerprint: string;
  structural_signature: string;
  canonical_finding_id: string;
  member_finding_ids: string[];
  occurrence_count: number;
  repositories: string[];
  vulnerability_type: string;
  representative_finding: unknown;
  match_reasons: string[];
}

export interface DeduplicationResult {
  total_findings: number;
  unique_findings: number;
  duplicate_findings: number;
  groups: DeduplicationGroup[];
}

export function deduplicateFindings(
  findingIds: string[],
  scanRunId?: string,
): Promise<DeduplicationResult> {
  /* Optional scan_run_id (Phase 14J): when present the backend validates the
     run's explicit lineage and records the DEDUPLICATE stage execution. */
  const payload: { finding_ids: string[]; scan_run_id?: string } = {
    finding_ids: findingIds,
  };
  if (scanRunId) payload.scan_run_id = scanRunId;
  return requestJson<DeduplicationResult>("/api/deduplicate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}