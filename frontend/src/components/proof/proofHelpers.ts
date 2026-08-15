/* Presentation helpers for the Proof page. These format backend values
   only - proof status, duration and policy are never computed here. */

import {
  confidenceLabel,
  formatDate,
  priorityTone,
  proofStatusLabel,
  proofTone,
  shortFindingId,
  verdictLabel,
  verdictTone,
} from "../validation/validationHelpers";

export {
  confidenceLabel,
  formatDate,
  priorityTone,
  proofStatusLabel,
  proofTone,
  shortFindingId,
  verdictLabel,
  verdictTone,
};

export function formatDuration(durationMs: number): string {
  if (durationMs < 1000) {
    return `${Math.round(durationMs)}ms`;
  }
  if (durationMs >= 60000) {
    return `${(durationMs / 60000).toFixed(1)}m`;
  }
  return `${(durationMs / 1000).toFixed(2)}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(0)} KiB`;
  }
  return `${bytes} bytes`;
}
