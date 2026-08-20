/* Hook for security report generation. */

import { useCallback, useState } from "react";

import { downloadReport, type ReportRequest } from "../api/report";

export interface UseReportGeneration {
  generating: boolean;
  error: string | null;
  generatePdf: (projectId?: string) => Promise<void>;
  generateJson: (projectId?: string) => Promise<void>;
  clearError: () => void;
}

export function useReportGeneration(): UseReportGeneration {
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = useCallback(
    async (format: "pdf" | "json", projectId?: string) => {
      setGenerating(true);
      setError(null);
      try {
        const request: ReportRequest = { format };
        if (projectId) {
          request.project_id = projectId;
        }
        const timestamp = new Date().toISOString().slice(0, 10);
        const filename = projectId
          ? `security-report-${projectId.slice(0, 8)}-${timestamp}.${format}`
          : `security-report-all-${timestamp}.${format}`;
        await downloadReport(request, filename);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "report generation failed";
        setError(message);
      } finally {
        setGenerating(false);
      }
    },
    [],
  );

  const generatePdf = useCallback(
    (projectId?: string) => generate("pdf", projectId),
    [generate],
  );

  const generateJson = useCallback(
    (projectId?: string) => generate("json", projectId),
    [generate],
  );

  const clearError = useCallback(() => setError(null), []);

  return { generating, error, generatePdf, generateJson, clearError };
}
