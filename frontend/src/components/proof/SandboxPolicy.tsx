import type { SandboxPolicyInfo } from "../../api/proof";
import { formatBytes } from "./proofHelpers";

export interface SandboxPolicyProps {
  policy: SandboxPolicyInfo | null;
}

export function SandboxPolicy({ policy }: SandboxPolicyProps) {
  if (policy === null) return null;
  return (
    <>
      <h4 className="pf-summary__subtitle">Sandbox Policy</h4>
      <dl className="pf-policy">
        <div className="pf-policy__row">
          <dt>Network</dt>
          <dd>{policy.network_enabled ? "Enabled" : "Disabled"}</dd>
        </div>
        <div className="pf-policy__row">
          <dt>Loopback Allowed</dt>
          <dd>{policy.allow_loopback ? "Yes" : "No"}</dd>
        </div>
        <div className="pf-policy__row">
          <dt>Timeout</dt>
          <dd>{policy.timeout_seconds}s</dd>
        </div>
        <div className="pf-policy__row">
          <dt>Max Output</dt>
          <dd>{formatBytes(policy.max_output_bytes)}</dd>
        </div>
        <div className="pf-policy__row">
          <dt>Max Processes</dt>
          <dd>{policy.max_processes}</dd>
        </div>
      </dl>
    </>
  );
}
