import type { ProofRow } from "../../api/proof";
import { SandboxPolicy } from "./SandboxPolicy";

export interface ProofSummaryProps {
  row: ProofRow;
}

export function ProofSummary({ row }: ProofSummaryProps) {
  const hasSummary = row.summary !== null && row.summary !== "";
  return (
    <details
      className="pf-summary"
      onClick={(event) => event.stopPropagation()}
    >
      <summary className="pf-summary__summary">Summary</summary>
      <div className="pf-summary__panel">
        {!hasSummary ? (
          <p className="pf-summary__empty">No proof summary available</p>
        ) : (
          <p className="pf-summary__text">{row.summary}</p>
        )}
        {row.error !== null && row.error !== "" ? (
          <p className="pf-summary__error">{row.error}</p>
        ) : null}
        <SandboxPolicy policy={row.sandbox_policy} />
      </div>
    </details>
  );
}
