import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";
import { formatConfidence } from "../findings/findingsHelpers";
import { formatTimestamp, verdictLabel } from "./detailHelpers";

export function ValidationPanel({
  detail,
  onValidate,
  validating = false,
  validateError = null,
  disabled = false,
}: {
  detail: FindingDetail;
  onValidate?: () => void;
  validating?: boolean;
  validateError?: string | null;
  /** Disable the action until a scan-run context is selected (Phase 14K). */
  disabled?: boolean;
}) {
  const validation = detail.validation;
  const interactive = typeof onValidate === "function";

  if (!validation) {
    return (
      <Card title="Validation">
        <div className="fd-panel__body">
          <p className="fd-panel__empty">Not validated</p>
          {interactive && validateError ? (
            <p className="fd-panel__error" role="alert">
              Unable to validate: {validateError}
            </p>
          ) : null}
          {interactive ? (
            <div className="fd-panel__actions">
              <Button
                size="sm"
                variant="secondary"
                disabled={validating || disabled}
                onClick={onValidate}
              >
                {validating ? "Validating\u2026" : "Validate"}
              </Button>
            </div>
          ) : null}
        </div>
      </Card>
    );
  }

  return (
    <Card title="Validation">
      <div className="fd-panel__body">
        <div className="fd-panel__line">
          <span className="fd-panel__label">Verdict</span>
          <Badge
            tone={
              validation.verdict === "true_positive"
                ? "success"
                : validation.verdict === "false_positive"
                  ? "info"
                  : "warning"
            }
          >
            {verdictLabel(validation.verdict)}
          </Badge>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Confidence</span>
          <span className="fd-panel__value">
            {formatConfidence(validation.confidence)}
          </span>
        </div>
        <div className="fd-panel__line">
          <span className="fd-panel__label">Validated At</span>
          <span className="fd-panel__value fd-panel__mono">
            {formatTimestamp(validation.validated_at)}
          </span>
        </div>
        {interactive ? (
          <p className="fd-validation__available" role="status">
            Validation Available
          </p>
        ) : null}
        <h4 className="fd-validation__subtitle">Reasoning</h4>
        <p className="fd-validation__reasoning">
          {validation.reasoning?.trim()
            ? validation.reasoning
            : "No validation reasoning available"}
        </p>
        {validation.evidence_used.length > 0 ? (
          <>
            <h4 className="fd-validation__subtitle">Evidence Used</h4>
            <ul className="fd-validation__evidence">
              {validation.evidence_used.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </>
        ) : null}
        <p className="fd-validation__note">
          The verdict is the backend&apos;s judgment of the existing evidence,
          not new frontend analysis.
        </p>
      </div>
    </Card>
  );
}