/* Typed API client for findings. Mirrors the backend response models in
   app/api/findings_models.py (GET /api/findings). The optional project_id
   scopes the list to one repository via the backend's explicit scan
   lineage (404 for an unknown project - never a silent global fallback). */


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

export class FindingsRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "FindingsRequestError";
    this.status = status;
  }
}

export function getFindings(projectId?: string): Promise<FindingListItem[]> {
  const url = projectId
    ? `/api/findings?project_id=${encodeURIComponent(projectId)}`
    : "/api/findings";
  return fetch(url).then((response) => {
    if (!response.ok) {
      throw new FindingsRequestError(
        response.status,
        `request failed: ${url} (${response.status})`,
      );
    }
    return response.json() as Promise<FindingListItem[]>;
  });
}