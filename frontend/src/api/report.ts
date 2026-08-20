/* Typed API client for security report generation. */

export interface ReportRequest {
  project_id?: string;
  format: "pdf" | "json";
}

export async function generateReport(
  request: ReportRequest,
): Promise<Blob> {
  const response = await fetch("/api/reports/generate", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    credentials: "include",
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "request failed" }));
    throw new Error(error.detail || `report generation failed: ${response.status}`);
  }

  return response.blob();
}

export async function downloadReport(
  request: ReportRequest,
  filename?: string,
): Promise<void> {
  const blob = await generateReport(request);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename || `security-report.${request.format}`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
