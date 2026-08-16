import { useCallback, useState } from "react";

import { runValidation as runValidationApi } from "../api/findingValidate";
import { ProjectRequestError } from "../api/projects";

export interface ValidateState {
  loading: boolean;
  error: string | null;
}

const IDLE: ValidateState = { loading: false, error: null };

/* One manual VALIDATE action per finding: a single POST to the existing
   backend endpoint. The backend calls the LLM provider and returns the
   verdict; nothing here guesses verdicts or runs timers in the browser. */
export function useValidateFinding() {
  const [state, setState] = useState<ValidateState>(IDLE);

  /* ``scanRunId`` is the explicitly selected scan-run context (Phase 14K):
     it is sent verbatim so the backend records the VALIDATE execution.
     Never inferred client-side. */
  const runValidation = useCallback(
    async (findingId: string, scanRunId?: string): Promise<boolean> => {
      setState({ loading: true, error: null });
      try {
        await runValidationApi(findingId, scanRunId);
        setState(IDLE);
        return true;
      } catch (error) {
        const detail =
          error instanceof ProjectRequestError
            ? error.message
            : "request failed";
        setState({ loading: false, error: detail });
        return false;
      }
    },
    [],
  );

  return { validating: state.loading, error: state.error, runValidation };
}