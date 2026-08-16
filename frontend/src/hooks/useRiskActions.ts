import { useCallback, useState } from "react";

import {
  assessRisk as assessRiskApi,
  checkSla as checkSlaApi,
  createSla as createSlaApi,
} from "../api/risk";
import { ProjectRequestError } from "../api/projects";

export interface ActionState {
  loading: boolean;
  error: string | null;
}

const IDLE: ActionState = { loading: false, error: null };

/* Per-finding risk/SLA actions. Each action is one POST to the existing
   backend endpoints; the backend calculates risk scores, priorities,
   deadlines and breach state. Nothing here computes values or runs
   timers in the browser. */
export function useRiskActions() {
  const [risk, setRisk] = useState<ActionState>(IDLE);
  const [sla, setSla] = useState<ActionState>(IDLE);
  const [check, setCheck] = useState<ActionState>(IDLE);

  const runAction = useCallback(
    async (
      setState: (state: ActionState) => void,
      request: () => Promise<unknown>,
    ): Promise<boolean> => {
      setState({ loading: true, error: null });
      try {
        await request();
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

  /* ``scanRunId`` is the explicitly selected scan-run context (Phase 14J):
     it is sent verbatim to the backend, which records the action as an
     execution of that stage against the run. Never inferred client-side. */
  const assess = useCallback(
    (findingId: string, scanRunId?: string) =>
      runAction(setRisk, () => assessRiskApi(findingId, scanRunId)),
    [runAction],
  );

  const startSla = useCallback(
    (findingId: string, scanRunId?: string) =>
      runAction(setSla, () => createSlaApi(findingId, scanRunId)),
    [runAction],
  );

  const checkSla = useCallback(
    (findingId: string, scanRunId?: string) =>
      runAction(setCheck, () => checkSlaApi(findingId, scanRunId)),
    [runAction],
  );

  return { risk, sla, check, assess, startSla, checkSla };
}