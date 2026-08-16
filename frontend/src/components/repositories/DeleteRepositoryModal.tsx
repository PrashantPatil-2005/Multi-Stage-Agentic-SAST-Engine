import { useEffect, useRef, useState } from "react";

import { deleteProject, ProjectRequestError } from "../../api/projects";
import type { RepositorySummary } from "../../api/repositories";
import { Button } from "../ui/Button";
import "./add-repository-modal.css";

export interface DeleteRepositoryModalProps {
  repository: RepositorySummary;
  onClose: () => void;
  onDeleted: (repository: RepositorySummary) => void;
}

export function DeleteRepositoryModal({
  repository,
  onClose,
  onDeleted,
}: DeleteRepositoryModalProps) {
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<Element | null>(null);

  useEffect(() => {
    previousFocusRef.current = document.activeElement;
    dialogRef.current
      ?.querySelector<HTMLButtonElement>(".repo-modal__cancel")
      ?.focus();
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

  async function handleConfirm() {
    if (submitting) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      await deleteProject(repository.project_id);
      onDeleted(repository);
    } catch (error) {
      setSubmitError(
        error instanceof ProjectRequestError ? error.message : "request failed",
      );
      setSubmitting(false);
    }
  }

  return (
    <div
      className="repo-modal__backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget && !submitting) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="delete-repository-modal-title"
        className="repo-modal"
        ref={dialogRef}
      >
        <h2 id="delete-repository-modal-title" className="repo-modal__title">
          Delete repository
        </h2>
        <p className="repo-modal__prompt">
          Delete <strong>{repository.name}</strong>? This permanently removes
          the repository and everything it owns: its prepared snapshot, scan
          runs and execution history, findings, deduplication membership, risk,
          SLA, validation, proof and approval records.
        </p>

        {submitError ? (
          <p role="alert" className="repo-modal__error">
            Unable to delete repository: {submitError}
          </p>
        ) : null}

        <div className="repo-modal__actions">
          <Button
            variant="secondary"
            className="repo-modal__cancel"
            disabled={submitting}
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={submitting}
            onClick={handleConfirm}
          >
            {submitting ? "Deleting\u2026" : "Delete Repository"}
          </Button>
        </div>
      </div>
    </div>
  );
}
