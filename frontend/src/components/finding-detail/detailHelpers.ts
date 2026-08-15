/* Display helpers for the finding detail page.

   The derived status uses deriveDisplayStatusCore from findingsHelpers.ts —
   the exact same precedence mapping as the Phase 3 findings list. All other
   labels are pure presentation of backend values; nothing is invented here.
*/

import type { FindingDetail } from "../../api/findingDetail";
import { deriveDisplayStatusCore } from "../findings/findingsHelpers";
import type { DisplayStatus } from "../findings/findingsHelpers";

export function deriveDetailStatus(detail: FindingDetail): DisplayStatus {
  return deriveDisplayStatusCore(
    detail.approval?.status,
    detail.proof?.status,
    detail.validation?.verdict,
  );
}

export function verdictLabel(verdict: string): string {
  switch (verdict) {
    case "true_positive":
      return "TRUE POSITIVE";
    case "false_positive":
      return "FALSE POSITIVE";
    case "uncertain":
      return "UNCERTAIN";
    default:
      return verdict.toUpperCase();
  }
}

export function proofStatusLabel(status: string): string {
  switch (status) {
    case "verified":
      return "VERIFIED";
    case "not_verified":
      return "NOT VERIFIED";
    case "blocked":
      return "BLOCKED";
    case "error":
      return "ERROR";
    default:
      return status.toUpperCase();
  }
}

export function approvalStatusLabel(status: string): string {
  switch (status) {
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    case "changes_requested":
      return "Changes Requested";
    default:
      return status;
  }
}

export function stepTypeLabel(stepType: string): string {
  return stepType.toUpperCase().replace(/_/g, " ");
}

export function slaStatusLabel(status: string): string {
  switch (status) {
    case "active":
      return "Active";
    case "breached":
      return "Breached";
    case "resolved":
      return "Resolved";
    case "not_applicable":
      return "No SLA";
    default:
      return status;
  }
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export function formatEscalationLevel(value: number): string {
  if (value <= 0) return "—";
  return `Level ${value}`;
}
