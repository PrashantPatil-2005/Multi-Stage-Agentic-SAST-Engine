import { useCallback, useState } from "react";

import { proveFinding as proveFindingApi } from "../api/proofAction";
import { ProjectRequestError } from "../api/projects";

export interface ProveState {
  loading: boolean;
  error: string | null;
}

const IDLE: ProveState = { loading: false, error: null };

/* One manual PROVE action per finding: a single POST to the existing backend
   endpoint. The backend runs the sandboxed proof and returns the result;
   nothing here builds payloads, commands, or sandbox settings, and no
   timers or polling run in the browser. */
export function useProveFinding() {
  const [state, setState] = useState<ProveState>(IDLE);

  /* ``scanRunId`` is the explicitly selected scan-run context (Phase 14K):
     it is sent verbatim so the backend records the PROVE execution.
     Never inferred client-side. */
  const proveFinding = useCallback(
    async (findingId: string, scanRunId?: string): Promise<boolean> => {
      setState({ loading: true, error: null });
      try {
        await proveFindingApi(findingId, scanRunId);
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

  return { proving: state.loading, error: state.error, proveFinding };
}