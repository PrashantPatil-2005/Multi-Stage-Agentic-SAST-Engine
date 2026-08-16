/* Typed mutation client for the PROVE stage. Mirrors the backend contract in
   app/api/routes/proofs.py and app/prove/models.py. The backend owns proof
   planning, harness selection, sandbox creation, execution, timeout, output
   limits and the result; the frontend only submits the finding id. */

import type { FindingProofDetail } from "./findingDetail";
import { requestJson } from "./projects";

export function proveFinding(
  findingId: string,
  scanRunId?: string,
): Promise<FindingProofDetail> {
  /* Optional scan_run_id (Phase 14K): the backend validates the run's
     explicit lineage and records the PROVE stage execution. When absent the
     body is omitted entirely - the wire contract is unchanged. */
  const options: RequestInit = { method: "POST" };
  if (scanRunId) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify({ scan_run_id: scanRunId });
  }
  return requestJson<FindingProofDetail>(
    `/api/findings/${encodeURIComponent(findingId)}/prove`,
    options,
  );
}