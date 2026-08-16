import { useCallback, useState } from "react";

import { getFindings } from "../api/findings";
import { deduplicateFindings } from "../api/dedup";
import type { DeduplicationResult } from "../api/dedup";
import { getProjectDetail, ProjectRequestError } from "../api/projects";

export interface DeduplicationRun {
  loading: boolean;
  projectId: string | null;
  repoName: string | null;
  result: DeduplicationResult | null;
  error: string | null;
  noFindings: boolean;
}

const IDLE: DeduplicationRun = {
  loading: false,
  projectId: null,
  repoName: null,
  result: null,
  error: null,
  noFindings: false,
};

/* Executes one deduplication run for a repository: resolves the repository's
   finding ids through the existing read-only endpoints (project snapshot
   files intersected with the findings list - the same path-membership
   convention the backend uses), then POSTs them to /api/deduplicate.
   No fingerprints, grouping or other dedup logic runs in the browser. */
export function useDeduplication() {
  const [run, setRun] = useState<DeduplicationRun>(IDLE);

  const execute = useCallback(
    async (projectId: string, repoName: string): Promise<void> => {
      setRun({
        loading: true,
        projectId,
        repoName,
        result: null,
        error: null,
        noFindings: false,
      });
      try {
        const [detail, findings] = await Promise.all([
          getProjectDetail(projectId),
          getFindings(),
        ]);
        const files = new Set(detail.files.map((file) => file.path));
        const findingIds = findings
          .filter((finding) => files.has(finding.file))
          .map((finding) => finding.finding_id);
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
        const result = await deduplicateFindings(findingIds);
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

  const reset = useCallback(() => setRun(IDLE), []);

  return { ...run, execute, reset };
}