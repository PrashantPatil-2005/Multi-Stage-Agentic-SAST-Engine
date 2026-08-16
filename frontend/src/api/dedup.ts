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
): Promise<DeduplicationResult> {
  return requestJson<DeduplicationResult>("/api/deduplicate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_ids: findingIds }),
  });
}