import { useCallback, useEffect, useState } from "react";

import { getScanFindings, getScanRun } from "../api/scans";
import type { ScanFinding, ScanRunDetail } from "../api/scans";
import { ProjectRequestError } from "../api/projects";

export interface ScanRunState {
  detail: ScanRunDetail | null;
  findings: ScanFinding[] | null;
  loading: boolean;
  error: boolean;
  notFound: boolean;
  reload: () => void;
}

/** Loads one scan run plus the findings it produced (explicit lineage).
    404 -> ``notFound``; both values come from the backend, never inferred. */
export function useScanRun(scanRunId: string): ScanRunState {
  const [detail, setDetail] = useState<ScanRunDetail | null>(null);
  const [findings, setFindings] = useState<ScanFinding[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [notFound, setNotFound] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(false);
    setNotFound(false);
    Promise.all([getScanRun(scanRunId), getScanFindings(scanRunId)])
      .then(([runDetail, runFindings]) => {
        if (cancelled) return;
        setDetail(runDetail);
        setFindings(runFindings);
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        if (reason instanceof ProjectRequestError && reason.status === 404) {
          setNotFound(true);
        } else {
          setError(true);
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanRunId, attempt]);

  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  return { detail, findings, loading, error, notFound, reload };
}
