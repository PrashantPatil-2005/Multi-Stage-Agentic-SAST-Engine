import { useEffect, useRef, useState } from "react";

import { useAuth } from "../../context/AuthContext";
import { Button } from "../ui/Button";
import { approvalActionLabel } from "./approvalsHelpers";
import type { DecisionKind } from "./ApprovalActions";

export interface ApprovalModalProps {
  kind: DecisionKind;
  findingLabel: string;
  action: string;
  priority: string | null;
  submitting: boolean;
  error: string | null;
  onConfirm: (reason: string) => void;
  onClose: () => void;
}

const KIND_META: Record<
  DecisionKind,
  { title: string; confirm: string; prompt: string }
> = {
  approve: {
    title: "Approve security action?",
    confirm: "Approve",
    prompt: "Authorizing this action records your approval in the audit trail.",
  },
  reject: {
    title: "Reject security action?",
    confirm: "Reject",
    prompt: "Rejecting records your decision in the audit trail.",
  },
  "request-changes": {
    title: "Request changes?",
    confirm: "Request Changes",
    prompt:
      "Send this approval back for changes. The analyst can resubmit for a new review cycle.",
  },
  resubmit: {
    title: "Resubmit for review?",
    confirm: "Resubmit",
    prompt:
      "Start a new review cycle once the requested changes are in place.",
  },
};

export function ApprovalModal({
  kind,
  findingLabel,
  action,
  priority,
  submitting,
  error,
  onConfirm,
  onClose,
}: ApprovalModalProps) {
  const { user } = useAuth();
  const meta = KIND_META[kind];
  const [reason, setReason] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<Element | null>(null);

  useEffect(() => {
    previousFocusRef.current = document.activeElement;
    textareaRef.current?.focus();
    return () => {
      if (previousFocusRef.current instanceof HTMLElement) {
        previousFocusRef.current.focus();
      }
    };
  }, []);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !submitting) {
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const dialog = dialogRef.current;
      if (dialog === null) return;
      const focusable = dialog.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || active === dialog)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || active === dialog)) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onClose, submitting]);

  const trimmedReason = reason.trim();
  const canSubmit = trimmedReason.length > 0 && trimmedReason.length <= 500;

  function handleSubmit() {
    if (!canSubmit || submitting) return;
    onConfirm(trimmedReason);
  }

  return (
    <div
      className="ap-modal__backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget && !submitting) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="approval-modal-title"
        className="ap-modal"
        ref={dialogRef}
      >
        <h2 id="approval-modal-title" className="ap-modal__title">
          {meta.title}
        </h2>
        <dl className="ap-modal__summary">
          <div className="ap-modal__row">
            <dt>Finding</dt>
            <dd>{findingLabel}</dd>
          </div>
          <div className="ap-modal__row">
            <dt>Action</dt>
            <dd>{approvalActionLabel(action)}</dd>
          </div>
          {priority ? (
            <div className="ap-modal__row">
              <dt>Priority</dt>
              <dd>{priority}</dd>
            </div>
          ) : null}
        </dl>
        <p className="ap-modal__prompt">{meta.prompt}</p>

        <p className="ap-modal__identity">
          This decision is recorded under{" "}
          <span className="ap-modal__identity-mono">
            {user?.display_name ?? user?.username ?? "unknown"}
          </span>.
        </p>

        <label className="ap-modal__field" htmlFor="approval-reason">
          Reason
        </label>
        <textarea
          id="approval-reason"
          ref={textareaRef}
          className="ap-modal__textarea"
          rows={4}
          required
          aria-required="true"
          maxLength={500}
          value={reason}
          disabled={submitting}
          onChange={(event) => setReason(event.target.value)}
        />
        <p className="ap-modal__hint">
          {trimmedReason.length === 0
            ? "A reason is required for the audit trail."
            : `${reason.length}/500 characters`}
        </p>

        {error ? (
          <p role="alert" className="ap-modal__error">
            {error}
          </p>
        ) : null}

        <div className="ap-modal__actions">
          <Button variant="secondary" disabled={submitting} onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={kind === "reject" ? "danger" : "primary"}
            disabled={!canSubmit || submitting}
            onClick={handleSubmit}
          >
            {submitting ? "Saving\u2026" : meta.confirm}
          </Button>
        </div>
      </div>
    </div>
  );
}
