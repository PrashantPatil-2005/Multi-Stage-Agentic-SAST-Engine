import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { createProject, ProjectRequestError } from "../../api/projects";
import { Button } from "../ui/Button";
import "./add-repository-modal.css";

export interface AddRepositoryModalProps {
  onClose: () => void;
  onCreated: () => void;
}

const NAME_MAX_LENGTH = 200;

export function AddRepositoryModal({
  onClose,
  onCreated,
}: AddRepositoryModalProps) {
  const [name, setName] = useState("");
  const [gitUrl, setGitUrl] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [urlTouched, setUrlTouched] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<Element | null>(null);

  const trimmedName = name.trim();
  const trimmedUrl = gitUrl.trim();
  const nameEmpty = trimmedName.length === 0;
  const nameTooLong = name.length > NAME_MAX_LENGTH;
  const urlEmpty = trimmedUrl.length === 0;
  const nameInvalid = nameTouched && (nameEmpty || nameTooLong);
  const urlInvalid = urlTouched && urlEmpty;
  const canSubmit = !nameEmpty && !nameTooLong && !urlEmpty && !submitting;

  useEffect(() => {
    previousFocusRef.current = document.activeElement;
    dialogRef.current
      ?.querySelector<HTMLInputElement>("#add-repository-name")
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

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setSubmitError(null);
    try {
      await createProject({
        name: trimmedName,
        source_type: "git",
        location: trimmedUrl,
        language: "python",
      });
      onCreated();
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
        aria-labelledby="add-repository-modal-title"
        className="repo-modal"
        ref={dialogRef}
      >
        <h2 id="add-repository-modal-title" className="repo-modal__title">
          Add repository
        </h2>
        <p className="repo-modal__prompt">
          Register a Git repository for security scanning. The repository is
          prepared when you add it.
        </p>
        <form onSubmit={handleSubmit} noValidate>
          <label className="repo-modal__field" htmlFor="add-repository-name">
            Repository name
          </label>
          <input
            id="add-repository-name"
            className="repo-modal__input"
            type="text"
            required
            maxLength={NAME_MAX_LENGTH}
            value={name}
            disabled={submitting}
            aria-required="true"
            aria-invalid={nameInvalid || undefined}
            aria-describedby={
              nameInvalid ? "add-repository-name-error" : undefined
            }
            onChange={(event) => setName(event.target.value)}
            onBlur={() => setNameTouched(true)}
          />
          {nameInvalid ? (
            <p id="add-repository-name-error" className="repo-modal__field-error">
              {nameEmpty
                ? "Repository name is required."
                : `Repository name must be at most ${NAME_MAX_LENGTH} characters.`}
            </p>
          ) : null}

          <label
            className="repo-modal__field repo-modal__field--stacked"
            htmlFor="add-repository-url"
          >
            Git repository URL
          </label>
          <input
            id="add-repository-url"
            className="repo-modal__input"
            type="text"
            inputMode="url"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            required
            value={gitUrl}
            disabled={submitting}
            aria-required="true"
            aria-invalid={urlInvalid || undefined}
            aria-describedby={
              urlInvalid ? "add-repository-url-error" : "add-repository-url-hint"
            }
            onChange={(event) => setGitUrl(event.target.value)}
            onBlur={() => setUrlTouched(true)}
          />
          {urlInvalid ? (
            <p id="add-repository-url-error" className="repo-modal__field-error">
              Git repository URL is required.
            </p>
          ) : null}
          <p id="add-repository-url-hint" className="repo-modal__hint">
            Provide a Git repository URL supported by the server's Git client.
          </p>

          {submitError ? (
            <p role="alert" className="repo-modal__error">
              Unable to add repository: {submitError}
            </p>
          ) : null}

          <div className="repo-modal__actions">
            <Button variant="secondary" disabled={submitting} onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              disabled={!canSubmit}
            >
              {submitting ? "Preparing\u2026" : "Add Repository"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}