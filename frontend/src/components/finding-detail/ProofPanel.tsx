import type { FindingDetail } from "../../api/findingDetail";
import { formatConfidence } from "../findings/findingsHelpers";
import { formatBytes, formatDuration } from "../proof/proofHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { formatTimestamp, proofStatusLabel } from "./detailHelpers";

export function ProofPanel({
  detail,
  onProve,
  proving = false,
  proveError = null,
  disabled = false,
}: {
  detail: FindingDetail;
  onProve?: () => void;
  proving?: boolean;
  proveError?: string | null;
  /** Disable the action until a scan-run context is selected (Phase 14K). */
  disabled?: boolean;
}) {
  const proof = detail.proof;
  const validation = detail.validation;
  const interactive = typeof onProve === "function";
  const verdict = validation?.verdict ?? null;
  const eligible = verdict === "true_positive";
  const showProve = interactive && !proof && eligible;

  if (!proof) {
    return (
      <Card title="Proof">
        <div className="fd-panel__body">
          <p className="fd-panel__empty">No proof result</p>
          {!validation ? (
            <p className="fd-proof__prereq">
              Proof requires a validation result. Validate the finding before
              proving.
            </p>
          ) : !eligible ? (
            <p className="fd-proof__prereq">
              Finding is not eligible for proof: verdict={verdict}
            </p>
          ) : null}
          {showProve && proveError ? (
            <p className="fd-panel__error" role="alert">
              Unable to prove finding: {proveError}
            </p>
          ) : null}
          {showProve ? (
            <div className="fd-panel__actions">
              <Button
                size="sm"
                variant="secondary"
                disabled={proving || disabled}
                onClick={onProve}
              >
                {proving ? "Proving\u2026" : "Prove Finding"}
              </Button>
            </div>
          ) : null}
        </div>
      </Card>
    );
  }

  return (
    <Card title="Proof">
      <div className="fd-panel__body">
        <div className="fd-panel__line">
          <span className="fd-panel__label">Proof Status</span>
          <Badge tone={proof.status === "verified" ? "success" : "warning"}>
            {proofStatusLabel(proof.status)}
          </Badge>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Confidence</span>
          <span className="fd-panel__value">
            {formatConfidence(proof.confidence)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Completed At</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatTimestamp(proof.created_at)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Duration</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatDuration(proof.duration_ms)}
          </span>
        </div>
        {interactive ? (
          <p className="fd-proof__available" role="status">
            Proof Result Available
          </p>
        ) : null}
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
                <dt>Max Output</dt>
                <dd className="fd-kv__mono">
                  {formatBytes(proof.sandbox_policy.max_output_bytes)}
                </dd>
              </div>
              <div className="fd-kv__row">
                <dt>Max Processes</dt>
                <dd className="fd-kv__mono">{proof.sandbox_policy.max_processes}</dd>
              </div>
            </dl>
          </>
        ) : null}
        <p className="fd-proof__note">
          This is a safe summary of the proof result. Raw payloads, artifacts
          and sandbox internals are intentionally not exposed.
        </p>
      </div>
    </Card>
  );
}