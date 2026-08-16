import { Link } from "react-router-dom";

import type { RepositorySummary } from "../../api/repositories";
import { formatDate, priorityTone } from "../risk/riskHelpers";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { RepositoryStatus } from "./RepositoryStatus";

export const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"];

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function Dash() {
  return <span aria-hidden="true">{"\u2014"}</span>;
}

function CountText({ label, count }: { label: string; count: number }) {
  return (
    <span className="repo-count">
      {label} {count}
    </span>
  );
}

function FindingsCell({ row }: { row: RepositorySummary }) {
  if (row.findings === null) return <Dash />;
  const nonZero = PRIORITIES.filter(
    (priority) => (row.findings?.by_priority[priority] ?? 0) > 0,
  );
  return (
    <span className="repo-findings">
      <span className="repo-findings__total">{row.findings.total}</span>
      {nonZero.length > 0 ? (
        <span className="repo-findings__badges">
          {nonZero.map((priority) => (
            <Badge
              key={priority}
              tone={priorityTone(priority)}
              aria-label={`${priority}: ${row.findings!.by_priority[priority]}`}
            >
              {priority} {row.findings!.by_priority[priority]}
            </Badge>
          ))}
        </span>
      ) : null}
    </span>
  );
}

function PriorityCell({ row }: { row: RepositorySummary }) {
  const priority = row.findings?.highest_priority ?? null;
  if (priority === null) return <Dash />;
  const badge = (
    <Badge tone={priorityTone(priority)}>{priority}</Badge>
  );
  const topFindingId = row.risk?.top_finding_id ?? null;
  if (topFindingId === null) return badge;
  return (
    <Link
      to={`/findings/${topFindingId}`}
      aria-label={`Open highest priority finding ${topFindingId}`}
    >
      {badge}
    </Link>
  );
}

function RiskCell({ row }: { row: RepositorySummary }) {
  if (row.risk === null) return <Dash />;
  return (
    <span className="repo-risk">
      {row.risk.highest_risk_score !== null ? (
        <span className="repo-risk__score">
          Score {row.risk.highest_risk_score}
        </span>
      ) : null}
      {row.risk.highest_priority !== null ? (
        <span className="repo-risk__priority">
          {row.risk.highest_priority}
        </span>
      ) : null}
    </span>
  );
}

function ValidationCell({ row }: { row: RepositorySummary }) {
  if (row.validation === null) return <Dash />;
  return (
    <span className="repo-sums">
      <CountText label="True positive" count={row.validation.true_positive} />
      <CountText label="False positive" count={row.validation.false_positive} />
      <CountText label="Uncertain" count={row.validation.uncertain} />
    </span>
  );
}

function ProofCell({ row }: { row: RepositorySummary }) {
  if (row.proof === null) return <Dash />;
  return (
    <span className="repo-sums">
      <CountText label="Verified" count={row.proof.verified} />
      <CountText label="Not verified" count={row.proof.not_verified} />
      <CountText label="Blocked" count={row.proof.blocked} />
      <CountText label="Error" count={row.proof.error} />
    </span>
  );
}

function SlaCell({ row }: { row: RepositorySummary }) {
  if (row.sla === null) return <Dash />;
  return (
    <span className="repo-sums">
      <CountText label="Active" count={row.sla.active} />
      <CountText label="Breached" count={row.sla.breached} />
      <CountText label="Resolved" count={row.sla.resolved} />
    </span>
  );
}

function RepositoryName({ row }: { row: RepositorySummary }) {
  return (
    <span className="repo-name">
      <Link
        to={`/findings?project_id=${encodeURIComponent(row.project_id)}`}
        className="repo-name__link"
      >
        {row.name}
      </Link>
      <span className="repo-name__meta">
        {row.source_type}
        {row.language ? ` · ${row.language}` : ""}
      </span>
    </span>
  );
}

export function RepositoryTable({
  repositories,
  scanningProjectIds,
  onScan,
  deduplicatingProjectIds,
  onDeduplicate,
  deletingProjectIds,
  onDelete,
}: {
  repositories: RepositorySummary[];
  scanningProjectIds: ReadonlySet<string>;
  onScan: (row: RepositorySummary) => void;
  deduplicatingProjectIds: ReadonlySet<string>;
  onDeduplicate: (row: RepositorySummary) => void;
  deletingProjectIds: ReadonlySet<string>;
  onDelete: (row: RepositorySummary) => void;
}) {
  return (
    <>
      <div className="repo-table-wrap">
        <table className="repo-table">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Project ID</th>
              <th scope="col">Status</th>
              <th scope="col">Findings</th>
              <th scope="col">Highest Priority</th>
              <th scope="col">Risk</th>
              <th scope="col">Validation</th>
              <th scope="col">Proof</th>
              <th scope="col">SLA</th>
              <th scope="col">Created</th>
              <th scope="col">Scan</th>
              <th scope="col">Dedup</th>
              <th scope="col">Delete</th>
            </tr>
          </thead>
          <tbody>
            {repositories.map((row) => (
              <tr key={row.project_id}>
                <td>
                  <RepositoryName row={row} />
                </td>
                <td>
                  <span
                    className="repo-id"
                    title={row.project_id}
                    aria-label={`Project ${row.project_id}`}
                  >
                    {shortId(row.project_id)}
                  </span>
                </td>
                <td>
                  <RepositoryStatus status={row.status} />
                </td>
                <td>
                  <FindingsCell row={row} />
                </td>
                <td>
                  <PriorityCell row={row} />
                </td>
                <td>
                  <RiskCell row={row} />
                </td>
                <td>
                  <ValidationCell row={row} />
                </td>
                <td>
                  <ProofCell row={row} />
                </td>
                <td>
                  <SlaCell row={row} />
                </td>
                <td>{formatDate(row.created_at)}</td>
                <td>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={scanningProjectIds.has(row.project_id)}
                    onClick={() => onScan(row)}
                    aria-label={`Scan repository ${row.name}`}
                  >
                    {scanningProjectIds.has(row.project_id)
                      ? "Scanning\u2026"
                      : "Scan"}
                  </Button>
                </td>
                <td>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={deduplicatingProjectIds.has(row.project_id)}
                    onClick={() => onDeduplicate(row)}
                    aria-label={`Deduplicate repository ${row.name}`}
                  >
                    {deduplicatingProjectIds.has(row.project_id)
                      ? "Deduplicating\u2026"
                      : "Deduplicate"}
                  </Button>
                </td>
                <td>
                  <Button
                    size="sm"
                    variant="danger"
                    disabled={deletingProjectIds.has(row.project_id)}
                    onClick={() => onDelete(row)}
                    aria-label={`Delete repository ${row.name}`}
                  >
                    {deletingProjectIds.has(row.project_id)
                      ? "Deleting\u2026"
                      : "Delete"}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="repo-cards">
        {repositories.map((row) => (
          <li className="repo-card" key={row.project_id}>
            <div className="repo-card__header">
              <RepositoryName row={row} />
              <span className="repo-card__status">
                <RepositoryStatus status={row.status} />
              </span>
            </div>
            <dl className="repo-card__grid">
              <div className="repo-card__item">
                <dt>Project ID</dt>
                <dd title={row.project_id}>{shortId(row.project_id)}</dd>
              </div>
              <div className="repo-card__item">
                <dt>Findings</dt>
                <dd>
                  <FindingsCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>Highest Priority</dt>
                <dd>
                  <PriorityCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>Risk</dt>
                <dd>
                  <RiskCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>Validation</dt>
                <dd>
                  <ValidationCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>Proof</dt>
                <dd>
                  <ProofCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>SLA</dt>
                <dd>
                  <SlaCell row={row} />
                </dd>
              </div>
              <div className="repo-card__item">
                <dt>Created</dt>
                <dd>{formatDate(row.created_at)}</dd>
              </div>
            </dl>
            <div className="repo-card__actions">
              <Button
                size="sm"
                variant="secondary"
                disabled={scanningProjectIds.has(row.project_id)}
                onClick={() => onScan(row)}
                aria-label={`Scan repository ${row.name}`}
              >
                {scanningProjectIds.has(row.project_id)
                  ? "Scanning\u2026"
                  : "Scan"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={deduplicatingProjectIds.has(row.project_id)}
                onClick={() => onDeduplicate(row)}
                aria-label={`Deduplicate repository ${row.name}`}
              >
                {deduplicatingProjectIds.has(row.project_id)
                  ? "Deduplicating\u2026"
                  : "Deduplicate"}
              </Button>
              <Button
                size="sm"
                variant="danger"
                disabled={deletingProjectIds.has(row.project_id)}
                onClick={() => onDelete(row)}
                aria-label={`Delete repository ${row.name}`}
              >
                {deletingProjectIds.has(row.project_id)
                  ? "Deleting\u2026"
                  : "Delete"}
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
