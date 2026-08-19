/* Typed API client for the DefectDojo integration.
   Mirrors the backend response models in app/defectdojo/models.py
   and the endpoints in app/api/routes/defectdojo.py. */

export interface DefectDojoStatus {
  enabled: boolean;
  configured: boolean;
  url: string;
  product_id: number | null;
  engagement_id: number | null;
  ticket_count: number;
  tickets_with_error: number;
}

export interface DefectDojoConnectionTest {
  success: boolean;
  message: string;
  url: string;
  version: string | null;
}

export interface DefectDojoTicket {
  finding_id: string;
  defectdojo_finding_id: number | null;
  defectdojo_url: string;
  status: "pending" | "created" | "synced" | "error";
  error_message: string | null;
  created_at: string | null;
  updated_at: string | null;
  payload: Record<string, unknown>;
}

export interface DefectDojoSyncResult {
  total: number;
  created: number;
  updated: number;
  errors: number;
  tickets: DefectDojoTicket[];
  error_messages: string[];
}

export class DefectDojoApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "DefectDojoApiError";
  }
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string" && body.detail.trim() !== "") {
      return body.detail;
    }
  } catch {
    // non-JSON error body
  }
  return `request failed (${response.status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: "include" });
  if (!response.ok) {
    throw new DefectDojoApiError(response.status, await errorDetail(response));
  }
  return (await response.json()) as T;
}

export function getDefectDojoStatus(): Promise<DefectDojoStatus> {
  return request<DefectDojoStatus>("/api/defectdojo/status");
}

export function testDefectDojoConnection(): Promise<DefectDojoConnectionTest> {
  return request<DefectDojoConnectionTest>("/api/defectdojo/test-connection", {
    method: "POST",
  });
}

export function createDefectDojoTicket(
  findingId: string,
): Promise<DefectDojoTicket> {
  return request<DefectDojoTicket>(
    `/api/defectdojo/create/${encodeURIComponent(findingId)}`,
    { method: "POST" },
  );
}

export function syncDefectDojoFindings(): Promise<DefectDojoSyncResult> {
  return request<DefectDojoSyncResult>("/api/defectdojo/sync", {
    method: "POST",
  });
}

export function getDefectDojoTickets(): Promise<DefectDojoTicket[]> {
  return request<DefectDojoTicket[]>("/api/defectdojo/tickets");
}

export function getDefectDojoTicketForFinding(
  findingId: string,
): Promise<DefectDojoTicket> {
  return request<DefectDojoTicket>(
    `/api/defectdojo/tickets/${encodeURIComponent(findingId)}`,
  );
}
