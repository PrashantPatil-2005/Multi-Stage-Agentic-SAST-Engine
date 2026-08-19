/* Typed API client for repository (project) ingestion and scanning.
   Mirrors the backend response models in app/api/schemas.py
   (POST /api/projects, POST /api/projects/{id}/scan). */

export type SourceType = "directory" | "zip" | "git";

export interface ProjectInput {
  name: string;
  source_type: SourceType;
  location: string;
  language: "python";
}

export interface SnapshotSummary {
  fetched_files: number;
  fetched_bytes: number;
  python_files: number;
  parse_failures: number;
  total_lines: number;
  function_count: number;
  class_count: number;
  call_count: number;
  import_count: number;
  assignment_count: number;
}

export interface ProjectOut {
  id: string;
  name: string;
  source_type: string;
  location: string;
  language: string;
  status: string;
  created_at: string;
  summary: SnapshotSummary;
}

export interface FileMeta {
  path: string;
  sha256: string;
  line_count: number;
  functions: number;
  classes: number;
  imports: number;
  calls: number;
  assignments: number;
  error: string | null;
}

export interface ProjectDetail {
  id: string;
  name: string;
  source_type: string;
  location: string;
  language: string;
  status: string;
  created_at: string;
  summary: SnapshotSummary;
  files: FileMeta[];
}

export interface ScanResponse {
  report_id: string;
  scan_run_id: string;
  project_id: string;
  created_at: string;
  scanned_file_count: number;
  total_findings: number;
  by_type: Record<string, number>;
  finding_ids: string[];
}

export class ProjectRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ProjectRequestError";
    this.status = status;
  }
}

async function errorDetail(response: Response, path: string): Promise<string> {
  let detail: unknown = null;
  try {
    const body = (await response.json()) as { detail?: unknown };
    detail = body.detail;
  } catch {
    // non-JSON error body; falls through to the generic message below
  }
  if (typeof detail === "string" && detail.trim() !== "") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "object" && item !== null && "msg" in item) {
          return String((item as { msg: unknown }).msg);
        }
        return String(item);
      })
      .filter((part) => part.trim() !== "");
    if (parts.length > 0) {
      return parts.join("; ");
    }
  }
  return `request failed: ${path} (${response.status})`;
}

export async function requestJson<T>(path: string, init: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, credentials: "include" });
  if (!response.ok) {
    throw new ProjectRequestError(await errorDetail(response, path), response.status);
  }
  return (await response.json()) as T;
}

export function createProject(input: ProjectInput): Promise<ProjectOut> {
  return requestJson<ProjectOut>("/api/projects", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function scanProject(projectId: string): Promise<ScanResponse> {
  return requestJson<ScanResponse>(
    `/api/projects/${encodeURIComponent(projectId)}/scan`,
    { method: "POST" },
  );
}

/** Re-run PREPARE against the existing workspace repo copy (no re-fetch). */
export function reprepareProject(projectId: string): Promise<ProjectOut> {
  return requestJson<ProjectOut>(
    `/api/projects/${encodeURIComponent(projectId)}/reprepare`,
    { method: "POST" },
  );
}

export function getProjectDetail(projectId: string): Promise<ProjectDetail> {
  return requestJson<ProjectDetail>(
    `/api/projects/${encodeURIComponent(projectId)}`,
    { method: "GET" },
  );
}

export async function deleteProject(projectId: string): Promise<void> {
  const response = await fetch(`/api/projects/${encodeURIComponent(projectId)}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!response.ok) {
    throw new ProjectRequestError(
      await errorDetail(response, `/api/projects/${projectId}`),
      response.status,
    );
  }
}