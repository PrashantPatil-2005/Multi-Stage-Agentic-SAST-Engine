/* Typed API client for the human approval workflow.
   Mirrors the backend contracts in app/api/routes/approval.py. */

import { fetchJson } from "./dashboard";

export type ApprovalStatus = "pending" | "approved" | "rejected" | "changes_requested";

export type ApprovalDecisionKind = "approve" | "reject" | "request-changes" | "resubmit";

/** Reviewer identity recorded on every decision until real auth lands. */
export const REVIEWER = "security-analyst";

export const APPROVAL_ACTION_LABEL: Record<string, string> = {
  remediation: "Remediation",
  other: "Other",
};

export const APPROVAL_STATUS_LABEL: Record<ApprovalStatus, string> = {
  pending: "Pending",
  approved: "Approved",
  rejected: "Rejected",
  changes_requested: "Changes Requested",
};

export interface ApprovalRequest {
  id: string;
  finding_id: string;
  status: ApprovalStatus;
  requested_at: string;
  requested_by: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
  reason: string | null;
  action: string;
  version: number;
  /** Explicit scan-run context the approval workflow was requested against. */
  scan_run_id?: string | null;
}

export interface ApprovalEvent {
  id: string;
  approval_id: string;
  finding_id: string;
  previous_status: string | null;
  new_status: string;
  actor: string;
  reason: string | null;
  created_at: string;
}

export interface ApprovalListItem {
  approval_id: string;
  finding_id: string;
  status: ApprovalStatus;
  action: string;
  version: number;
  requested_by: string;
  requested_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  reason: string | null;
  vulnerability_type: string | null;
  severity: string | null;
  priority: string | null;
  risk_score: number | null;
  repository: string | null;
  file: string | null;
}

export interface ApprovalDecision {
  reviewed_by: string;
  reason: string;
}

export class ApprovalApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApprovalApiError";
  }
}

function readableDetail(detail: unknown): string {
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item: { msg?: string; loc?: unknown[] }) => {
        const where = Array.isArray(item.loc)
          ? item.loc.map(String).filter((part) => part !== "body").join(".")
          : "";
        return where ? `${where}: ${item.msg ?? "invalid"}` : item.msg ?? "invalid";
      })
      .filter(Boolean);
    if (messages.length > 0) return messages.join("; ");
  }
  if (typeof detail === "string") return detail;
  return "";
}

export function getApprovals(): Promise<ApprovalListItem[]> {
  return fetchJson<ApprovalListItem[]>("/api/approvals");
}

export function getApprovalForFinding(findingId: string): Promise<ApprovalRequest> {
  return fetchJson<ApprovalRequest>(
    `/api/findings/${encodeURIComponent(findingId)}/approval`,
  );
}

export function getApprovalHistory(approvalId: string): Promise<ApprovalEvent[]> {
  return fetchJson<ApprovalEvent[]>(
    `/api/approvals/${encodeURIComponent(approvalId)}/history`,
  );
}

export async function submitApprovalDecision(
  approvalId: string,
  kind: ApprovalDecisionKind,
  decision: ApprovalDecision,
): Promise<ApprovalRequest> {
  const response = await fetch(
    `/api/approvals/${encodeURIComponent(approvalId)}/${kind}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(decision),
    },
  );
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = readableDetail((payload as { detail?: unknown } | null)?.detail);
    throw new ApprovalApiError(
      response.status,
      detail || `Approval update failed (HTTP ${response.status}).`,
    );
  }
  return payload as ApprovalRequest;
}

/** Creates a remediation approval request for a finding through the backend
    approval workflow. The body mirrors the backend defaults; the optional
    scan_run_id (Phase 14K) records the APPROVAL stage execution against the
    explicitly selected run. */
export async function createApprovalRequest(
  findingId: string,
  scanRunId?: string,
): Promise<ApprovalRequest> {
  const payload: { action: string; requested_by: string; scan_run_id?: string } = {
    action: "remediation",
    requested_by: "system",
  };
  if (scanRunId) payload.scan_run_id = scanRunId;
  const response = await fetch(
    `/api/findings/${encodeURIComponent(findingId)}/approval`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
  const payloadJson: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = readableDetail(
      (payloadJson as { detail?: unknown } | null)?.detail,
    );
    throw new ApprovalApiError(
      response.status,
      detail || `Approval request failed (HTTP ${response.status}).`,
    );
  }
  return payloadJson as ApprovalRequest;
}
