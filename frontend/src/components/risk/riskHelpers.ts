/* Presentation helpers for the Risk & SLA page. These format backend
   values only - no risk score, priority or SLA computation happens here. */

export function formatRemaining(seconds: number | null): string {
  if (seconds === null) return "\u2014";
  if (seconds <= 0) return "Due now";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0 && minutes > 0) return `${hours}h ${minutes}m remaining`;
  if (hours > 0) return `${hours}h remaining`;
  if (minutes > 0) return `${minutes}m remaining`;
  return `${seconds}s remaining`;
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  }).format(date);
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    timeZone: "UTC",
  }).format(date);
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
    case "none":
      return "None";
    default:
      return status;
  }
}

export function validationLabel(verdict: string | null): string {
  switch (verdict) {
    case "true_positive":
      return "True Positive";
    case "false_positive":
      return "False Positive";
    case "uncertain":
      return "Uncertain";
    default:
      return "\u2014";
  }
}

export function proofLabel(status: string | null): string {
  switch (status) {
    case "verified":
      return "Verified";
    case "not_verified":
      return "Not Verified";
    case "blocked":
      return "Blocked";
    case "error":
      return "Error";
    default:
      return "\u2014";
  }
}

export function factorLabel(name: string): string {
  return name.charAt(0).toUpperCase() + name.slice(1).replace(/_/g, " ");
}

export function priorityTone(priority: string): "danger" | "warning" | "neutral" {
  if (priority === "P0" || priority === "P1") return "danger";
  if (priority === "P2") return "warning";
  return "neutral";
}

export function slaTone(status: string): "danger" | "success" | "info" | "neutral" {
  switch (status) {
    case "breached":
      return "danger";
    case "active":
      return "info";
    case "resolved":
      return "success";
    default:
      return "neutral";
  }
}
