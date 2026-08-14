/* Display helpers for the findings table/cards.

   Derived display status — based ONLY on existing backend state, with this
   documented precedence (first match wins):

   1. approval approved        -> "Approved"
   2. approval rejected        -> "Rejected"
   3. approval pending/changes -> "Pending Approval"
   4. proof verified           -> "Proven"
   5. verdict true/false pos.  -> "Validated"  (a definitive verdict exists)
   6. verdict uncertain        -> "Uncertain"
   7. nothing recorded         -> "Detected"

   No new backend state is invented; this is a pure presentation mapping.
*/

import type { FindingListItem } from "../../api/findings";

export type DisplayStatus =
  | "Detected"
  | "Validated"
  | "Uncertain"
  | "Proven"
  | "Pending Approval"
  | "Approved"
  | "Rejected";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

export const PRIORITY_RANK: Record<string, number> = {
  P0: 0,
  P1: 1,
  P2: 2,
  P3: 3,
  P4: 4,
};

export const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function formatSeverity(severity: string): string {
  return severity.toUpperCase();
}

export function severityRank(severity: string): number {
  return SEVERITY_RANK[formatSeverity(severity)] ?? 9;
}

export function priorityRank(priority: string | null): number {
  if (priority === null) return 9;
  return PRIORITY_RANK[priority] ?? 9;
}

export function vulnLabel(vulnerabilityType: string): string {
  switch (vulnerabilityType) {
    case "sql_injection":
      return "SQL Injection";
    case "command_injection":
      return "Command Injection";
    case "ssrf":
      return "SSRF";
    default:
      return vulnerabilityType;
  }
}

export function formatConfidence(confidence: number | null): string {
  if (confidence === null) return "—";
  return `${Math.round(confidence * 100)}%`;
}

export function deriveDisplayStatus(finding: FindingListItem): DisplayStatus {
  switch (finding.approval_status) {
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    case "pending":
    case "changes_requested":
      return "Pending Approval";
    default:
      break;
  }
  if (finding.proof_status === "verified") return "Proven";
  if (finding.verdict === "true_positive" || finding.verdict === "false_positive") {
    return "Validated";
  }
  if (finding.verdict === "uncertain") return "Uncertain";
  return "Detected";
}

export function formatSlaRemaining(seconds: number): string {
  if (seconds >= 3600) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return minutes > 0 ? `${hours}h ${minutes}m remaining` : `${hours}h remaining`;
  }
  if (seconds >= 60) {
    return `${Math.floor(seconds / 60)}m remaining`;
  }
  return `${seconds}s remaining`;
}

export function slaStatus(finding: FindingListItem): {
  label: string;
  breached: boolean;
} {
  switch (finding.sla.status) {
    case "active":
      return { label: "Active", breached: false };
    case "breached":
      return { label: "SLA Breached", breached: true };
    case "resolved":
      return { label: "Resolved", breached: false };
    default:
      return { label: "No SLA", breached: false };
  }
}

export function priorityTone(priority: string | null): BadgeTone {
  if (priority === "P0" || priority === "P1") return "danger";
  if (priority === "P2") return "warning";
  return "neutral";
}

export function severityTone(severity: string): BadgeTone {
  switch (formatSeverity(severity)) {
    case "CRITICAL":
      return "danger";
    case "HIGH":
      return "warning";
    case "MEDIUM":
      return "info";
    default:
      return "neutral";
  }
}

export function statusTone(status: DisplayStatus): BadgeTone {
  switch (status) {
    case "Approved":
    case "Proven":
    case "Validated":
      return "success";
    case "Uncertain":
    case "Pending Approval":
      return "warning";
    case "Rejected":
      return "danger";
    default:
      return "neutral";
  }
}