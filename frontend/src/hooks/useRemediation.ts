/* Stateful hooks for the remediation workflow (propose / apply / verify). */

import { useCallback, useState } from "react";

import {
  applyRemediation,
  getRemediation,
  proposeRemediation,
  verifyRemediation,
  type RemediationRecord,
} from "../api/remediation";

export interface UseRemediationResult {
  record: RemediationRecord | null;
  recordError: string | null;
  recordLoading: boolean;
  loadRecord: () => Promise<void>;
  proposing: boolean;
  applying: boolean;
  verifying: boolean;
  actionError: string | null;
  lastAction: "propose" | "apply" | "verify" | null;
  propose: () => Promise<boolean>;
  apply: (confirm: boolean) => Promise<boolean>;
  verify: () => Promise<boolean>;
  clearActionError: () => void;
}

export function useRemediation(findingId: string): UseRemediationResult {
  const [record, setRecord] = useState<RemediationRecord | null>(null);
  const [recordError, setRecordError] = useState<string | null>(null);
  const [recordLoading, setRecordLoading] = useState(false);
  const [proposing, setProposing] = useState(false);
  const [applying, setApplying] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [lastAction, setLastAction] = useState<
    "propose" | "apply" | "verify" | null
  >(null);

  const loadRecord = useCallback(async () => {
    setRecordLoading(true);
    setRecordError(null);
    try {
      const next = await getRemediation(findingId);
      setRecord(next);
    } catch (error) {
      if (error instanceof Error && "status" in error && error.status === 404) {
        setRecord(null);
      } else {
        setRecordError("unable to load remediation record");
      }
    } finally {
      setRecordLoading(false);
    }
  }, [findingId]);

  const propose = useCallback(async () => {
    setProposing(true);
    setActionError(null);
    try {
      setRecord(await proposeRemediation(findingId));
      setLastAction("propose");
      return true;
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "proposal failed",
      );
      return false;
    } finally {
      setProposing(false);
    }
  }, [findingId]);

  const apply = useCallback(
    async (confirm: boolean) => {
      setApplying(true);
      setActionError(null);
      try {
        setRecord(await applyRemediation(findingId, confirm));
        setLastAction("apply");
        return true;
      } catch (error) {
        setActionError(
          error instanceof Error ? error.message : "apply failed",
        );
        return false;
      } finally {
        setApplying(false);
      }
    },
    [findingId],
  );

  const verify = useCallback(async () => {
    setVerifying(true);
    setActionError(null);
    try {
      setRecord(await verifyRemediation(findingId));
      setLastAction("verify");
      return true;
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "verify failed",
      );
      return false;
    } finally {
      setVerifying(false);
    }
  }, [findingId]);

  const clearActionError = useCallback(() => setActionError(null), []);

  return {
    record,
    recordError,
    recordLoading,
    loadRecord,
    proposing,
    applying,
    verifying,
    actionError,
    lastAction,
    propose,
    apply,
    verify,
    clearActionError,
  };
}