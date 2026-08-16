import { useCallback, useState } from "react";

import { deduplicateFindings } from "../api/dedup";
import type { DeduplicationResult } from "../api/dedup";
import { getProjectScans, getScanFindings } from "../api/scans";
import type { ScanRun } from "../api/scans";
import { ProjectRequestError } from "../api/projects";

export interface DeduplicationRun {
  loading: boolean;
  projectId: string | null;
  repoName: string | null;
  result: DeduplicationResult | null;
  error: string | null;
  noFindings: boolean;
}

export interface DedupContext {
  projectId: string;
  repoName: string;
  runs: ScanRun[];
}

const IDLE: DeduplicationRun = {
  loading: false,
  projectId: null,
  repoName: null,
  result: null,
  error: null,
  noFindings: false,
};

/* Executes one deduplication run for a repository against an explicit scan
   run context (Phase 14J). The finding ids come from the backend's
   authoritative scan-run lineage (GET /api/scans/{id}/findings) - never from
   file paths or client-side attribution - and the same real scan_run_id is
   sent to /api/deduplicate so the backend records the DEDUPLICATE stage
   execution. When a repository has several scan runs the caller must pick
   one explicitly; a single run is unambiguous and is used automatically. */
export function useDeduplication() {
  const [run, setRun] = useState<DeduplicationRun>(IDLE);
  const [context, setContext] = useState<DedupContext | null>(null);

  const execute = useCallback(
    async (projectId: string, repoName: string, scanRunId: string) => {
      setRun({
        loading: true,
        projectId,
        repoName,
        result: null,
        error: null,
        noFindings: false,
      });
      try {
        const findings = await getScanFindings(scanRunId);
        const findingIds = findings.map((finding) => finding.id);
        if (findingIds.length === 0) {
          setRun({
            loading: false,
            projectId,
            repoName,
            result: null,
            error: null,
            noFindings: true,
          });
          return;
        }
        const result = await deduplicateFindings(findingIds, scanRunId);
        setRun({
          loading: false,
          projectId,
          repoName,
          result,
          error: null,
          noFindings: false,
        });
      } catch (error) {
        const detail =
          error instanceof ProjectRequestError
            ? error.message
            : "request failed";
        setRun({
          loading: false,
          projectId,
          repoName,
          result: null,
          error: detail,
          noFindings: false,
        });
      }
    },
    [],
  );

  /* Entry point for the repository "Deduplicate" action. Resolves the run
     context: zero runs -> nothing to deduplicate (honest empty state), one
     run -> use it directly (no ambiguity), several -> ask the caller to
     choose explicitly before any request is sent. */
  const begin = useCallback(
    async (projectId: string, repoName: string): Promise<void> => {
      setContext(null);
      setRun({
        loading: true,
        projectId,
        repoName,
        result: null,
        error: null,
        noFindings: false,
      });
      let runs: ScanRun[] = [];
      try {
        runs = await getProjectScans(projectId);
      } catch {
        runs = [];
      }
      if (runs.length > 1) {
        setRun(IDLE);
        setContext({ projectId, repoName, runs });
        return;
      }
      if (runs.length === 0) {
        setRun({
          loading: false,
          projectId,
          repoName,
          result: null,
          error: null,
          noFindings: true,
        });
        return;
      }
      await execute(projectId, repoName, runs[0].scan_run_id);
    },
    [execute],
  );

  const confirmContext = useCallback(
    async (scanRunId: string): Promise<void> => {
      if (!context) return;
      const { projectId, repoName } = context;
      setContext(null);
      await execute(projectId, repoName, scanRunId);
    },
    [context, execute],
  );

  const cancelContext = useCallback(() => setContext(null), []);

  const reset = useCallback(() => {
    setRun(IDLE);
    setContext(null);
  }, []);

  return { ...run, context, begin, execute, confirmContext, cancelContext, reset };
}
