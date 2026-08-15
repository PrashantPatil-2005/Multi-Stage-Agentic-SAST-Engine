/* Presentation helpers for the Validation page. These format backend
   values only - no verdicts, confidence or reasoning are computed here. */

import { formatDate as riskFormatDate, priorityTone } from "../risk/riskHelpers";

export { priorityTone };

export function formatDate(iso: string | null): string {
  return iso === null ? "\u2014" : riskFormatDate(iso);
}

export function verdictLabel(verdict: string | null): string {
  switch (verdict) {
    case "true_positive":
      return "TRUE POSITIVE";
    case "false_positive":
      return "FALSE POSITIVE";
    case "uncertain":
      return "UNCERTAIN";
    default:
      return "\u2014";
  }
}

export function verdictTone(
  verdict: string | null,
): "neutral" | "success" | "warning" | "danger" | "info" {
  switch (verdict) {
    case "true_positive":
      return "success";
    case "false_positive":
      return "info";
    case "uncertain":
      return "warning";
    default:
      return "neutral";
  }
}

export function proofStatusLabel(status: string | null): string {
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
      return "\u2014";
  }
}

export function proofTone(
  status: string | null,
): "neutral" | "success" | "warning" | "danger" | "info" {
  switch (status) {
    case "verified":
      return "success";
    case "not_verified":
      return "warning";
    case "blocked":
      return "warning";
    case "error":
      return "danger";
    default:
      return "neutral";
  }
}

export function confidenceLabel(confidence: number | null): string {
  if (confidence === null) return "\u2014";
  return `${Math.round(confidence * 100)}%`;
}

export function shortFindingId(findingId: string): string {
  return findingId.length > 12 ? `${findingId.slice(0, 12)}\u2026` : findingId;
}
