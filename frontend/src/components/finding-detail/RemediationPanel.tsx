import { useEffect, useState } from "react";

import { reprepareProject } from "../../api/projects";
import type { RemediationRecord } from "../../api/remediation";
import type { FindingDetail } from "../../api/findingDetail";
import { useRemediation } from "../../hooks/useRemediation";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { formatTimestamp } from "./detailHelpers";

const STRATEGY_LABELS: Record<string, string> = {
  parameterize_query: "Parameterized Query",
  shell_argument_vector: "Shell Argument Vector",
  shell_quote: "Shell-Quoted Argument",
  no_automatic_fix: "No Automatic Fix",
};

function statusTone(status: RemediationRecord["status"]): "success" | "danger" | "warning" | "neutral" {
  switch (status) {
    case "verified":
      return "success";
    case "applied":
      return "warning";
    case "still_present":
    case "error":
      return "danger";
    default:
      return "neutral";
  }
}

function statusLabel(status: RemediationRecord["status"]): string {
  switch (status) {
    case "proposed":
      return "Proposed";
    case "no_fix_available":
      return "No Automatic Fix";
    case "applied":
      return "Applied";
    case "verified":
      return "Verified";
    case "still_present":
      return "Still Present";
    case "error":
      return "Error";
  }
}

export function RemediationPanel({
  detail,
  onRemediationChanged,
  disabled = false,
}: {
  detail: FindingDetail;
  onRemediationChanged: () => void;
  /** Disable actions until a scan-run context is selected. */
  disabled?: boolean;
}) {
  const { record, loadRecord, proposing, applying, verifying, actionError, propose, apply, verify } =
    useRemediation(detail.finding_id);
  const [confirmed, setConfirmed] = useState(false);
  const [repreparing, setRepreparing] = useState(false);
  const [reprepareError, setReprepareError] = useState<string | null>(null);

  useEffect(() => {
    void loadRecord();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.finding_id]);

  const proposal = record?.proposal ?? detail.remediation?.proposal ?? null;
  const status = record?.status ?? detail.remediation?.status ?? null;
  const approval = detail.approval;
  const approvedForRemediation =
    approval?.status === "approved" && approval.action === "remediation";

  async function handlePropose() {
    if (await propose()) {
      setConfirmed(false);
      onRemediationChanged();
    }
  }

  async function handleApply() {
    if (await apply(true)) {
      setConfirmed(false);
      onRemediationChanged();
    }
  }

  async function handleReprepare() {
    if (!detail.project?.project_id) return;
    setRepreparing(true);
    setReprepareError(null);
    try {
      await reprepareProject(detail.project.project_id);
      onRemediationChanged();
    } catch (error) {
      setReprepareError(
        error instanceof Error ? error.message : "re-prepare failed",
      );
    } finally {
      setRepreparing(false);
    }
  }

  async function handleVerify() {
    if (await verify()) {
      onRemediationChanged();
    }
  }

  const gates: string[] = [];
  if (!approval) {
    gates.push("No approval request; remediation requires an approved approval.");
  } else if (!approvedForRemediation) {
    gates.push(
      `Approval is ${approval.status} (${approval.action}); remediation requires an approved approval with action "remediation".`,
    );
  } else if (disabled) {
    gates.push("Select a producing scan run before running remediation actions.");
  }

  return (
    <Card title="Remediation">
      <div className="fd-panel__body">
        {status === null ? (
          <>
            {gates.length > 0 ? (
              <p className="fd-approval__prereq">{gates[0]}</p>
            ) : (
              <>
                {actionError ? (
                  <p role="alert" className="fd-panel__error">
                    {actionError}
                  </p>
                ) : null}
                <p className="fd-panel__empty">No remediation record</p>
                <div className="fd-panel__actions">
                  <Button
                    variant="secondary"
                    disabled={proposing}
                    onClick={handlePropose}
                  >
                    {proposing ? "Generating Proposal\u2026" : "Generate Fix Proposal"}
                  </Button>
                </div>
              </>
            )}
          </>
        ) : (
          <>
            <div className="fd-panel__line">
              <span className="fd-panel__label">Remediation State</span>
              <Badge tone={statusTone(status)}>{statusLabel(status)}</Badge>
            </div>
            {status === "no_fix_available" && proposal ? (
              <p className="fd-approval__prereq">{proposal.rationale}</p>
            ) : null}
            {status === "error" && record?.error ? (
              <p role="alert" className="fd-panel__error">{record.error}</p>
            ) : null}

            {proposal ? (
              <>
                <div className="fd-panel__line">
                  <span className="fd-panel__label">Strategy</span>
                  <span className="fd-panel__value">
                    {STRATEGY_LABELS[proposal.strategy] ?? proposal.strategy}
                  </span>
                </div>
                <div className="fd-panel__line">
                  <span className="fd-panel__label">Target</span>
                  <span className="fd-panel__value fd-panel__mono">
                    {proposal.file}:{proposal.line}
                  </span>
                </div>
                {proposal.import_to_add ? (
                  <div className="fd-panel__line">
                    <span className="fd-panel__label">Import To Add</span>
                    <span className="fd-panel__value fd-panel__mono">
                      {proposal.import_to_add}
                    </span>
                  </div>
                ) : null}
                <div className="fd-remediation__diff">
                  <div className="fd-remediation__diff-line fd-remediation__diff-line--before">
                    <code>{proposal.before}</code>
                  </div>
                  <div className="fd-remediation__diff-line fd-remediation__diff-line--after">
                    <code>{proposal.after}</code>
                  </div>
                </div>
                <p className="fd-panel__reason">{proposal.rationale}</p>
              </>
            ) : null}

            {status === "proposed" ? (
              <>
                {actionError ? (
                  <p role="alert" className="fd-panel__error">
                    {actionError}
                  </p>
                ) : null}
                <label className="fd-remediation__confirm">
                  <input
                    type="checkbox"
                    checked={confirmed}
                    onChange={(event) => setConfirmed(event.target.checked)}
                  />
                  <span>
                    I understand this patches the private workspace copy only,
                    never the original source.
                  </span>
                </label>
                <div className="fd-panel__actions">
                  <Button
                    variant="secondary"
                    disabled={applying || !confirmed}
                    onClick={handleApply}
                  >
                    {applying ? "Applying Fix\u2026" : "Apply Fix to Workspace Copy"}
                  </Button>
                </div>
              </>
            ) : null}

            {status === "applied" ? (
              <>
                {record?.applied_by ? (
                  <div className="fd-panel__line">
                    <span className="fd-panel__label">Applied By</span>
                    <span className="fd-panel__value">{record.applied_by}</span>
                  </div>
                ) : null}
                {record?.applied_at ? (
                  <div className="fd-panel__line">
                    <span className="fd-panel__label">Applied At</span>
                    <span className="fd-panel__value fd-panel__mono">
                      {formatTimestamp(record.applied_at)}
                    </span>
                  </div>
                ) : null}
                {actionError ? (
                  <p role="alert" className="fd-panel__error">
                    {actionError}
                  </p>
                ) : null}
                {reprepareError ? (
                  <p role="alert" className="fd-panel__error">
                    {reprepareError}
                  </p>
                ) : null}
                <p className="fd-approval__prereq">
                  Re-run PREPARE against the patched workspace copy, then rescan
                  and verify the finding.
                </p>
                <div className="fd-panel__actions">
                  <Button
                    variant="secondary"
                    disabled={repreparing || !detail.project?.project_id}
                    onClick={handleReprepare}
                  >
                    {repreparing ? "Re-preparing\u2026" : "Re-prepare & Rescan"}
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={verifying}
                    onClick={handleVerify}
                  >
                    {verifying ? "Verifying\u2026" : "Verify Fix"}
                  </Button>
                </div>
              </>
            ) : null}

            {status === "verified" ? (
              <p className="fd-proof__available">
                Fix verified: a fresh scan no longer produces this finding.
              </p>
            ) : null}
            {status === "still_present" ? (
              <p className="fd-approval__prereq">
                The current snapshot still produces this finding. Re-prepare
                after applying the fix, then verify again.
              </p>
            ) : null}
            {record?.verified_at ? (
              <div className="fd-panel__line">
                <span className="fd-panel__label">Verified At</span>
                <span className="fd-panel__value fd-panel__mono">
                  {formatTimestamp(record.verified_at)}
                </span>
              </div>
            ) : null}
          </>
        )}
      </div>
    </Card>
  );
}