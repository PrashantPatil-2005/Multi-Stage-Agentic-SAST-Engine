import { Link } from "react-router-dom";

import { useScanHistory } from "../../hooks/useScanHistory";
import type { ScanRunStatus } from "../../api/scans";
import { formatDate } from "../risk/riskHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function statusTone(status: ScanRunStatus) {
  switch (status) {
    case "completed":
      return "success" as const;
    case "failed":
      return "danger" as const;
    case "running":
      return "warning" as const;
    default:
      return "neutral" as const;
  }
}

export function ScanHistory({
  projectId,
  projectName,
}: {
  projectId: string;
  projectName: string;
}) {
  const { runs, loading, error, reload } = useScanHistory(projectId);

  return (
    <Card aria-label={`Scan history for ${projectName}`}>
      <div className="repo-scan-history">
        <div className="repo-scan-history__head">
          <h2 className="repo-scan-history__title">Scan History</h2>
          <span className="repo-scan-history__repo">{projectName}</span>
          <Button size="sm" variant="secondary" onClick={reload}>
            Refresh
          </Button>
        </div>

        {loading ? (
          <p className="repo-scan-history__empty">{"Loading scan history\u2026"}</p>
        ) : error ? (
          <div className="repo-scan-error" role="alert">
            Unable to load scan history.
          </div>
        ) : runs === null || runs.length === 0 ? (
          <p className="repo-scan-history__empty">
            No scans have been run for this repository.
          </p>
        ) : (
          <table className="repo-scan-history__table">
            <thead>
              <tr>
                <th scope="col">Scan Run</th>
                <th scope="col">Status</th>
                <th scope="col">Started</th>
                <th scope="col">Completed</th>
                <th scope="col">Files</th>
                <th scope="col">Findings</th>
                <th scope="col">Run</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.scan_run_id}>
                  <td>
                    <span
                      className="repo-id"
                      title={run.scan_run_id}
                      aria-label={`Scan run ${run.scan_run_id}`}
                    >
                      {shortId(run.scan_run_id)}
                    </span>
                  </td>
                  <td>
                    <Badge tone={statusTone(run.status)}>{run.status}</Badge>
                  </td>
                  <td>{run.started_at ? formatDate(run.started_at) : "\u2014"}</td>
                  <td>
                    {run.completed_at ? formatDate(run.completed_at) : "\u2014"}
                  </td>
                  <td>
                    {run.scanned_file_count === null
                      ? "\u2014"
                      : run.scanned_file_count}
                  </td>
                  <td>
                    {run.total_findings === null ? "\u2014" : run.total_findings}
                  </td>
                  <td>
                    <Link
                      className="repo-scan-history__link"
                      to={`/scans/${encodeURIComponent(run.scan_run_id)}`}
                    >
                      View run
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {runs && runs.some((run) => run.status === "failed" && run.error) ? (
          <p className="repo-scan-history__error" role="alert">
            {runs
              .filter((run) => run.status === "failed" && run.error)
              .map((run) => run.error)
              .join(" \u00b7 ")}
          </p>
        ) : null}
      </div>
    </Card>
  );
}
