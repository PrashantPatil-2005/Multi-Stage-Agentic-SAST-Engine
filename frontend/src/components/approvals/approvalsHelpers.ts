/* Display helpers for the approval review queue. Pure presentation of
   backend values; nothing here invents state or bypasses the backend. */

import { APPROVAL_ACTION_LABEL, APPROVAL_STATUS_LABEL } from "../../api/approvals";
import type { ApprovalStatus } from "../../api/approvals";
import type { BadgeTone } from "../findings/findingsHelpers";

export const APPROVAL_TABS: ApprovalStatus[] = [
  "pending",
  "approved",
  "rejected",
  "changes_requested",
];

export function approvalStatusLabel(status: ApprovalStatus): string {
  return APPROVAL_STATUS_LABEL[status] ?? status;
}

export function approvalActionLabel(action: string): string {
  return APPROVAL_ACTION_LABEL[action] ?? action;
}

export function approvalStatusTone(status: ApprovalStatus): BadgeTone {
  switch (status) {
    case "pending":
      return "warning";
    case "approved":
      return "success";
    case "rejected":
      return "danger";
    case "changes_requested":
      return "info";
    default:
      return "neutral";
  }
}

const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/** Deterministic short date (UTC) for table cells: "Aug 15, 2026". */
export function formatRequestedDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${MONTHS[date.getUTCMonth()]} ${date.getUTCDate()}, ${date.getUTCFullYear()}`;
}

/** First 8 hex chars of the sha256 finding id, truncated for tables. */
export function shortFindingId(findingId: string): string {
  return `${findingId.slice(0, 8)}\u2026`;
}
