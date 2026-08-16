/* Typed mutation client for the VALIDATE stage. Mirrors the backend contract
   in app/api/routes/validations.py and app/validate/models.py. The backend
   runs the LLM validation and returns the verdict; the frontend only submits
   the finding id and the default provider. */

import type { ValidationResult } from "./findingDetail";
import { requestJson } from "./projects";

export function runValidation(
  findingId: string,
  scanRunId?: string,
): Promise<ValidationResult> {
  /* Optional scan_run_id (Phase 14K): the backend validates the run's
     explicit lineage and records the VALIDATE stage execution. The provider
     is always sent; scan_run_id is only added when a run context exists. */
  const payload: { provider: string; scan_run_id?: string } = {
    provider: "huggingface",
  };
  if (scanRunId) payload.scan_run_id = scanRunId;
  return requestJson<ValidationResult>(
    `/api/findings/${encodeURIComponent(findingId)}/validate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    },
  );
}