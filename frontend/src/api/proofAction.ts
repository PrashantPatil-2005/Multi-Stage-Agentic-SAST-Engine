/* Typed mutation client for the PROVE stage. Mirrors the backend contract in
   app/api/routes/proofs.py and app/prove/models.py. The backend owns proof
   planning, harness selection, sandbox creation, execution, timeout, output
   limits and the result; the frontend only submits the finding id. */

import type { FindingProofDetail } from "./findingDetail";
import { requestJson } from "./projects";

export function proveFinding(findingId: string): Promise<FindingProofDetail> {
  return requestJson<FindingProofDetail>(
    `/api/findings/${encodeURIComponent(findingId)}/prove`,
    { method: "POST" },
  );
}