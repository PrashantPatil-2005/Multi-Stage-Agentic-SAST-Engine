import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { formatTimestamp, proofStatusLabel } from "./detailHelpers";

export function ProofPanel({ detail }: { detail: FindingDetail }) {
  const proof = detail.proof;

  return (
    <Card title="Proof">
      {!proof ? (
        <p className="fd-panel__empty">No proof result</p>
      ) : (
        <div className="fd-panel__body">
          <div className="fd-panel__line">
            <span className="fd-panel__label">Proof Status</span>
            <Badge tone={proof.status === "verified" ? "success" : "warning"}>
              {proofStatusLabel(proof.status)}
            </Badge>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Completed At</span>
            <span className="fd-panel__value fd-panel__mono">
              {formatTimestamp(proof.created_at)}
            </span>
          </div>
          <h4 className="fd-proof__subtitle">Summary</h4>
          <p className="fd-proof__summary">{proof.summary || "—"}</p>
          {proof.error ? (
            <p className="fd-proof__error">{proof.error}</p>
          ) : null}
          {proof.sandbox_policy ? (
            <>
              <h4 className="fd-proof__subtitle">Sandbox Policy</h4>
              <dl className="fd-kv">
                <div className="fd-kv__row">
                  <dt>Network Enabled</dt>
                  <dd>{proof.sandbox_policy.network_enabled ? "Yes" : "No"}</dd>
                </div>
                <div className="fd-kv__row">
                  <dt>Loopback Allowed</dt>
                  <dd>{proof.sandbox_policy.allow_loopback ? "Yes" : "No"}</dd>
                </div>
                <div className="fd-kv__row">
                  <dt>Timeout</dt>
                  <dd className="fd-kv__mono">
                    {proof.sandbox_policy.timeout_seconds}s
                  </dd>
                </div>
                <div className="fd-kv__row">
                  <dt>Max Processes</dt>
                  <dd className="fd-kv__mono">{proof.sandbox_policy.max_processes}</dd>
                </div>
              </dl>
            </>
          ) : null}
        </div>
      )}
    </Card>
  );
}
