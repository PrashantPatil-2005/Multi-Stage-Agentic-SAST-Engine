/* Typed API client for the remediation workflow.
   Mirrors the backend response model in app/remediation/models.py and the
   endpoints in app/api/routes/remediation.py. */

export type RemediationStatus =
  | "proposed"
  | "no_fix_available"
  | "applied"
  | "verified"
  | "still_present"
  | "error";

export type RemediationStrategy =
  | "parameterize_query"
  | "shell_argument_vector"
  | "shell_quote"
  | "no_automatic_fix";

export interface RemediationProposal {
  finding_id: string;
  vulnerability_type: string;
  file: string;
  line: number;
  strategy: RemediationStrategy;
  before: string;
  after: string;
  import_to_add: string | null;
  rationale: string;
}

export interface RemediationRecord {
  finding_id: string;
  approval_id: string;
  status: RemediationStatus;
  proposal: RemediationProposal | null;
  applied_at: string | null;
  applied_by: string | null;
  verified_at: string | null;
  verification: string | null;
  error: string | null;
  created_at: string;
}

export class RemediationApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "RemediationApiError";
  }
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string" && body.detail.trim() !== "") {
      return body.detail;
    }
  } catch {
    // non-JSON error body; falls through to the generic message below
  }
  return `request failed (${response.status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: "include" });
  if (!response.ok) {
    throw new RemediationApiError(response.status, await errorDetail(response));
  }
  return (await response.json()) as T;
}

export function getRemediation(findingId: string): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/findings/${encodeURIComponent(findingId)}/remediation`,
  );
}

export function proposeRemediation(findingId: string): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/findings/${encodeURIComponent(findingId)}/remediation/proposal`,
    { method: "POST" },
  );
}

export function applyRemediation(
  findingId: string,
  confirm: boolean,
): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/findings/${encodeURIComponent(findingId)}/remediation/apply`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm }),
    },
  );
}

export function verifyRemediation(findingId: string): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/findings/${encodeURIComponent(findingId)}/remediation/verify`,
    { method: "POST" },
  );
}