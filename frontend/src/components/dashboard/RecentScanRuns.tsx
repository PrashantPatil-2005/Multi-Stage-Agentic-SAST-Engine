import { Link } from "react-router-dom";

import { useRecentScans } from "../../hooks/useRecentScans";
import type { ScanRun, ScanRunStatus } from "../../api/scans";
import { formatTimestamp } from "../risk/riskHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { Card } from "../ui/Card";

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function runTone(status: ScanRunStatus) {
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

export interface RecentScanRunsProps {
  /** project_id -> project name (authoritative, from the backend). */
  projectNames: ReadonlyMap<string, string>;
}

export function RecentScanRuns({ projectNames }: RecentScanRunsProps) {
  const { runs, loading, error, reload } = useRecentScans(5);

  return (
    <Card title="Recent Scan Runs">
      {loading ? (
        <p className="dash-empty" role="status">
          {"Loading recent scans\u2026"}
        </p>
      ) : error || runs === null ? (
        <div className="fd-panel__error" role="alert">
          Unable to load recent scans.{" "}
          <Button size="sm" variant="secondary" onClick={reload}>
            Retry
          </Button>
        </div>
      ) : runs.length === 0 ? (
        <p className="dash-empty" role="status">
          No scans have been run yet.
        </p>
      ) : (
        <ul className="dash-activity">
          {runs.map((run: ScanRun) => {
            const repoName = projectNames.get(run.project_id) ?? null;
            return (
              <li
                className="dash-activity__item"
                key={run.scan_run_id}
              >
                <Badge tone={runTone(run.status)}>{run.status}</Badge>
                <div className="dash-activity__body">
                  <span className="dash-activity__message">
                    {repoName ?? shortId(run.project_id)}
                  </span>
                  <span className="dash-activity__time">
                    {formatTimestamp(run.started_at)}
                    {run.total_findings !== null
                      ? ` \u00b7 ${run.total_findings} findings`
                      : ""}
                  </span>
                </div>
                <Link
                  className="dash-scan-link"
                  to={`/scans/${encodeURIComponent(run.scan_run_id)}`}
                  aria-label={`Open scan run ${run.scan_run_id}`}
                >
                  View
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
