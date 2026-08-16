/* Typed mutation client for the VALIDATE stage. Mirrors the backend contract
   in app/api/routes/validations.py and app/validate/models.py. The backend
   runs the LLM validation and returns the verdict; the frontend only submits
   the finding id and the default provider. */

import type { ValidationResult } from "./findingDetail";
import { requestJson } from "./projects";

export function runValidation(findingId: string): Promise<ValidationResult> {
  return requestJson<ValidationResult>(
    `/api/findings/${encodeURIComponent(findingId)}/validate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "huggingface" }),
    },
  );
}