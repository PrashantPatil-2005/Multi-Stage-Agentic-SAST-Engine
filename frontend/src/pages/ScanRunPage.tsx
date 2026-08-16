import { Link, useParams } from "react-router-dom";

import { useScanRun } from "../hooks/useScanRun";
import { useProject } from "../hooks/useProject";
import type { ScanRun as ScanRunRecord, ScanStageRun } from "../api/scans";
import { formatTimestamp } from "../components/risk/riskHelpers";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "./scan-run.css";

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function runTone(status: ScanRunRecord["status"]) {
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

function stageTone(status: ScanStageRun["status"]) {
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

function DetailItem({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <div className="scanrun-detail__item">
      <span className="scanrun-detail__label">{label}</span>
      <span className={`scanrun-detail__value${mono ? " scanrun-detail__value--mono" : ""}`}>
        {value ?? "\u2014"}
      </span>
    </div>
  );
}

function RepositoryLine({ projectId }: { projectId: string }) {
  const { project, loading } = useProject(projectId);
  if (loading) {
    return <span className="scanrun-detail__value">{"Loading\u2026"}</span>;
  }
  if (project === null) {
    return (
      <>
        <span className="scanrun-detail__value">{shortId(projectId)}</span>
        <Link
          className="ui-button ui-button--secondary ui-button--sm"
          to={`/repositories?project_id=${encodeURIComponent(projectId)}`}
        >
          Open Repository
        </Link>
      </>
    );
  }
  return (
    <>
      <Link
        className="scanrun-repo-link"
        to={`/repositories?project_id=${encodeURIComponent(projectId)}`}
      >
        {project.name}
      </Link>
      <Link
        className="ui-button ui-button--secondary ui-button--sm"
        to={`/repositories?project_id=${encodeURIComponent(projectId)}`}
      >
        Open Repository
      </Link>
    </>
  );
}

function ScanRunContent({ runId }: { runId: string }) {
  const { detail, findings, loading, error, notFound, reload } = useScanRun(runId);

  if (loading) {
    return (
      <div className="scanrun-page" aria-busy="true" aria-label="Loading scan run">
        <Card title="Scan Run">
          <div className="scanrun-skeleton" />
          <div className="scanrun-skeleton" />
        </Card>
        <Card title="Stages">
          <div className="scanrun-skeleton" />
        </Card>
      </div>
    );
  }

  if (notFound) {
    return (
      <Card>
        <div className="scanrun-error" role="alert" aria-label="Scan run not found">
          <p className="scanrun-error__text">Scan run not found.</p>
          <Link
            className="ui-button ui-button--secondary ui-button--md"
            to="/repositories"
          >
            Back to Repositories
          </Link>
        </div>
      </Card>
    );
  }

  if (error || detail === null) {
    return (
      <Card>
        <div className="scanrun-error" role="alert" aria-label="Scan run load error">
          <p className="scanrun-error__text">Unable to load scan run.</p>
          <Button variant="secondary" onClick={reload}>
            Retry
          </Button>
        </div>
      </Card>
    );
  }

  const run = detail.run;
  const runFindings = findings ?? [];

  return (
    <div className="scanrun-page">
      <Card title="Scan Run">
        <div className="scanrun-header">
          <p className="scanrun-run-id">
            Run ID:{" "}
            <span className="scanrun-run-id__value" title={run.scan_run_id}>
              {run.scan_run_id}
            </span>
          </p>
          <Badge tone={runTone(run.status)}>{run.status}</Badge>
        </div>
        <dl className="scanrun-detail">
          <div className="scanrun-detail__item">
            <span className="scanrun-detail__label">Repository</span>
            <RepositoryLine projectId={run.project_id} />
          </div>
          <DetailItem label="Started" value={formatTimestamp(run.started_at)} />
          <DetailItem
            label="Completed"
            value={run.completed_at ? formatTimestamp(run.completed_at) : null}
          />
          <DetailItem
            label="Files scanned"
            value={run.scanned_file_count === null ? null : String(run.scanned_file_count)}
          />
          <DetailItem
            label="Findings"
            value={run.total_findings === null ? null : String(run.total_findings)}
          />
        </dl>
        {run.error ? (
          <p className="scanrun-error-text" role="alert">
            {run.error}
          </p>
        ) : null}
      </Card>

      <Card title="Stages">
        <div className="scanrun-stages-scroll">
        <table className="scanrun-stages">
          <thead>
            <tr>
              <th scope="col">Stage</th>
              <th scope="col">Status</th>
              <th scope="col">Started</th>
              <th scope="col">Completed</th>
              <th scope="col">Executions</th>
              <th scope="col">Error</th>
            </tr>
          </thead>
          <tbody>
            {detail.stages.map((stage) => (
              <tr key={stage.stage_name}>
                <td>{stage.stage_name}</td>
                <td>
                  <Badge tone={stageTone(stage.status)}>{stage.status}</Badge>
                </td>
                <td>{stage.started_at ? formatTimestamp(stage.started_at) : "\u2014"}</td>
                <td>{stage.completed_at ? formatTimestamp(stage.completed_at) : "\u2014"}</td>
                <td>{stage.execution_count ?? 0}</td>
                <td>{stage.error ?? "\u2014"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        <p className="scanrun-stages__note">
          Executions counts every recorded run of a stage: PREPARE and SCAN
          record one per scan; DEDUPLICATE, RISK, SLA, VALIDATE, PROVE and
          APPROVAL record one per action explicitly executed against this
          run. Pending stages have never been executed.
        </p>
      </Card>

      <Card title="Stage Execution History">
        {(detail.executions ?? []).length === 0 ? (
          <p className="scanrun-findings__empty" role="status">
            No stage executions recorded yet.
          </p>
        ) : (
          <ul className="scanrun-history">
            {(detail.executions ?? []).map((execution) => (
              <li key={execution.execution_id} className="scanrun-history__item">
                <span className="scanrun-history__stage">
                  {execution.stage_name}
                </span>
                <Badge tone={stageTone(execution.status)}>
                  {execution.status}
                </Badge>
                <span className="scanrun-history__id" title={execution.execution_id}>
                  #{shortId(execution.execution_id)}
                </span>
                <span className="scanrun-history__time">
                  {formatTimestamp(execution.started_at)}
                </span>
                {execution.error ? (
                  <span className="scanrun-history__error" role="alert">
                    {execution.error}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        <p className="scanrun-stages__note">
          Execution history is append-only and backend-authoritative: retrying
          a failed stage keeps the failed attempt and adds a new record.
        </p>
      </Card>

      <Card title="Findings produced by this scan">
        {runFindings.length === 0 ? (
          <p className="scanrun-findings__empty" role="status">
            No findings were produced by this scan.
          </p>
        ) : (
          <ul className="scanrun-findings">
            {runFindings.map((finding) => (
              <li key={finding.id} className="scanrun-finding">
                <span className="scanrun-finding__id" title={finding.id}>
                  {shortId(finding.id)}
                </span>
                <span className="scanrun-finding__type">
                  {finding.vulnerability_type}
                </span>
                <span className="scanrun-finding__file">{finding.sink.file}</span>
                <Link
                  className="scanrun-finding__link"
                  to={`/findings/${encodeURIComponent(finding.id)}`}
                >
                  Open finding
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

export function ScanRunPage() {
  const { scanRunId } = useParams<{ scanRunId: string }>();
  if (!scanRunId) {
    return (
      <Card>
        <div className="scanrun-error" role="alert">
          <p className="scanrun-error__text">Scan run not found.</p>
        </div>
      </Card>
    );
  }
  return (
    <>
      <PageHeader
        title="Scan Run"
        description="Details of one repository scan execution"
      />
      <ScanRunContent runId={scanRunId} />
    </>
  );
}
