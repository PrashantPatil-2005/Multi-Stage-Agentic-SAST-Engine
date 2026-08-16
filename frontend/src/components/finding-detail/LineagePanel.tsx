import { Link } from "react-router-dom";

import type { FindingDetail } from "../../api/findingDetail";
import type { ScanRunStatus } from "../../api/scans";
import { formatTimestamp } from "../risk/riskHelpers";
import { Badge } from "../ui/Badge";
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

export function LineagePanel({ detail }: { detail: FindingDetail }) {
  const project = detail.project ?? null;
  const runs = detail.scan_runs ?? [];

  return (
    <Card title="Repository & Scan Lineage">
      <div className="fd-panel__body">
        {project === null ? (
          <p className="fd-panel__empty" role="status">
            Repository lineage unavailable.
          </p>
        ) : (
          <>
            <p className="fd-panel__line">
              <span className="fd-panel__label">Repository</span>
              <span className="fd-panel__value">{project.name}</span>
            </p>
            <p className="fd-panel__line">
              <span className="fd-panel__label">Language</span>
              <span className="fd-panel__value">{project.language}</span>
            </p>
            <p className="fd-panel__line">
              <span className="fd-panel__label">Source</span>
              <span className="fd-panel__value">{project.source_type}</span>
            </p>
            <p className="fd-panel__line">
              <span className="fd-panel__label">Location</span>
              <span className="fd-panel__value" title={project.location}>
                {project.location}
              </span>
            </p>
            <div className="fd-panel__actions">
              <Link
                className="ui-button ui-button--secondary ui-button--sm"
                to={`/repositories?project_id=${encodeURIComponent(project.project_id)}`}
              >
                Open Repository
              </Link>
            </div>
          </>
        )}

        <p className="fd-panel__label" style={{ margin: "12px 0 4px" }}>
          Producing scan runs
        </p>
        {runs.length === 0 ? (
          <p className="fd-panel__empty" role="status">
            Scan lineage unavailable.
          </p>
        ) : (
          <ul className="fd-panel__related">
            {runs.map((run) => (
              <li key={run.scan_run_id} className="fd-panel__line">
                <Link
                  className="fd-panel__link"
                  to={`/scans/${encodeURIComponent(run.scan_run_id)}`}
                  aria-label={`Scan run ${run.scan_run_id}`}
                >
                  #{shortId(run.scan_run_id)}
                </Link>
                <span>
                  <Badge tone={runTone(run.status)}>{run.status}</Badge>{" "}
                  <span className="fd-panel__value">
                    {formatTimestamp(run.started_at)}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
