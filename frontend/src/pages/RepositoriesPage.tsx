import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useRepositories } from "../hooks/useRepositories";
import { useDeduplication } from "../hooks/useDeduplication";
import type { RepositorySummary } from "../api/repositories";
import { scanProject, ProjectRequestError } from "../api/projects";
import type { ScanResponse } from "../api/projects";
import { AddRepositoryModal } from "../components/repositories/AddRepositoryModal";
import { PRIORITIES, RepositoryTable } from "../components/repositories/RepositoryTable";
import { RepositoryFilters } from "../components/repositories/RepositoryFilters";
import { RepositorySummary as RepositorySummaryCard } from "../components/repositories/RepositorySummary";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "../components/repositories/repositories.css";

interface FilterValues {
  q: string;
  priority: string;
  sla: string;
}

type ScanState =
  | { status: "scanning" }
  | { status: "success"; result: ScanResponse }
  | { status: "error"; detail: string };

interface LastScanInfo {
  projectId: string;
  repoName: string;
  result: ScanResponse;
}

interface ScanErrorInfo {
  projectId: string;
  detail: string;
}

const SCAN_TYPE_LABELS: Record<string, string> = {
  sql_injection: "SQL Injection",
  command_injection: "Command Injection",
  ssrf: "SSRF",
};

function SkeletonRow() {
  return (
    <tr aria-hidden="true">
      {Array.from({ length: 7 }).map((_, index) => (
        <td key={index}>
          <div className="repo-skeleton-line" />
        </td>
      ))}
    </tr>
  );
}

export function RepositoriesPage() {
  const { list, loading, error, reload } = useRepositories();
  const [searchParams, setSearchParams] = useSearchParams();
  const [addOpen, setAddOpen] = useState(false);
  const [addedMessage, setAddedMessage] = useState<string | null>(null);
  const [scans, setScans] = useState<Record<string, ScanState>>({});
  const [lastScan, setLastScan] = useState<LastScanInfo | null>(null);
  const [scanError, setScanError] = useState<ScanErrorInfo | null>(null);
  const [deduplicatingProjectIds, setDeduplicatingProjectIds] = useState<
    ReadonlySet<string>
  >(new Set());
  const dedup = useDeduplication();

  const filterValues: FilterValues = useMemo(
    () => ({
      q: searchParams.get("q") ?? "",
      priority: searchParams.get("priority") ?? "",
      sla: searchParams.get("sla") ?? "",
    }),
    [searchParams],
  );

  const repositories = list?.repositories ?? [];

  const filterOptions = useMemo(() => {
    const priorities = new Set<string>();
    const slaStatuses = new Set<string>();
    for (const row of repositories) {
      const highest = row.findings?.highest_priority;
      if (highest !== null && highest !== undefined) {
        priorities.add(highest);
      }
      if (row.sla !== null) {
        for (const [status, count] of Object.entries(row.sla!)) {
          if (status !== "available" && count > 0) slaStatuses.add(status);
        }
      }
    }
    return {
      priorities: PRIORITIES.filter((p) => priorities.has(p)),
      slaStatuses: ["active", "breached", "resolved"].filter((s) =>
        slaStatuses.has(s),
      ),
    };
  }, [repositories]);

  const matches = useMemo(() => {
    const q = filterValues.q.trim().toLowerCase();
    return repositories.filter((row) => {
      if (
        filterValues.priority !== "" &&
        row.findings?.highest_priority !== filterValues.priority
      ) {
        return false;
      }
      if (filterValues.sla !== "") {
        if (row.sla === null || row.sla[filterValues.sla as "active" | "breached" | "resolved"] <= 0) {
          return false;
        }
      }
      if (q) {
        const haystack = [
          row.name,
          row.project_id,
          row.location,
          row.source_type,
          row.language,
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [repositories, filterValues]);

  const summary = useMemo(
    () => ({
      repositoryCount: repositories.length,
      findingCount: repositories.reduce(
        (sum, row) => sum + (row.findings?.total ?? 0),
        0,
      ),
      assessedCount: repositories.filter((row) => row.risk !== null).length,
      breachCount: repositories.filter(
        (row) => row.sla !== null && row.sla.breached > 0,
      ).length,
    }),
    [repositories],
  );

  function patchFilters(patch: Partial<FilterValues>) {
    const next = new URLSearchParams(searchParams);
    (Object.entries(patch) as Array<[keyof FilterValues, string]>).forEach(
      ([key, value]) => {
        if (value === "") {
          next.delete(key);
        } else {
          next.set(key, value);
        }
      },
    );
    setSearchParams(next, { replace: true });
  }

  function openAddRepository() {
    setAddedMessage(null);
    setAddOpen(true);
  }

  function handleCreated() {
    setAddOpen(false);
    setAddedMessage("Repository added successfully.");
    reload();
  }

  const scanningProjectIds = useMemo(
    () =>
      new Set(
        Object.entries(scans)
          .filter(([, state]) => state.status === "scanning")
          .map(([projectId]) => projectId),
      ),
    [scans],
  );

  async function handleScan(row: RepositorySummary) {
    const projectId = row.project_id;
    if (scanningProjectIds.has(projectId)) return;
    setScans((prev) => ({ ...prev, [projectId]: { status: "scanning" } }));
    setScanError(null);
    try {
      const result = await scanProject(projectId);
      setScans((prev) => ({
        ...prev,
        [projectId]: { status: "success", result },
      }));
      setLastScan({ projectId, repoName: row.name, result });
      reload();
    } catch (error) {
      const detail =
        error instanceof ProjectRequestError
          ? error.message
          : "request failed";
      setScans((prev) => ({
        ...prev,
        [projectId]: { status: "error", detail },
      }));
      setScanError({ projectId, detail });
    }
  }

  async function handleDeduplicate(row: RepositorySummary) {
    const projectId = row.project_id;
    if (deduplicatingProjectIds.has(projectId)) return;
    setDeduplicatingProjectIds((prev) => new Set(prev).add(projectId));
    await dedup.execute(projectId, row.name);
    setDeduplicatingProjectIds((prev) => {
      const next = new Set(prev);
      next.delete(projectId);
      return next;
    });
  }

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Projects and repositories monitored by the security scanner"
        actions={
          <>
            <Button variant="primary" onClick={openAddRepository}>
              Add Repository
            </Button>
            <Button variant="secondary" onClick={reload} disabled={loading}>
              Refresh
            </Button>
          </>
        }
      />

      {addedMessage ? (
        <p className="repo-added" role="status">
          {addedMessage}
        </p>
      ) : null}

      {scanError ? (
        <div className="repo-scan-error" role="alert">
          Unable to scan repository: {scanError.detail}
        </div>
      ) : null}

      {lastScan ? (
        <div className="repo-scan-result" role="status">
          <div className="repo-scan-result__head">
            <span className="repo-scan-result__title">Scan completed</span>
            <span className="repo-scan-result__repo">{lastScan.repoName}</span>
          </div>
          <dl className="repo-scan-result__stats">
            <div>
              <dt>Files scanned</dt>
              <dd>{lastScan.result.scanned_file_count}</dd>
            </div>
            <div>
              <dt>Findings</dt>
              <dd>{lastScan.result.total_findings}</dd>
            </div>
          </dl>
          {lastScan.result.total_findings > 0 ? (
            <ul className="repo-scan-result__types">
              {Object.entries(lastScan.result.by_type).map(([type, count]) => (
                <li key={type}>
                  {SCAN_TYPE_LABELS[type] ?? type}: {count}
                </li>
              ))}
            </ul>
          ) : (
            <p className="repo-scan-result__none">
              Scan completed — no findings detected.
            </p>
          )}
          <div className="repo-scan-result__actions">
            <Link className="ui-button ui-button--primary" to="/findings">
              View Findings
            </Link>
          </div>
        </div>
      ) : null}

      {dedup.noFindings ? (
        <div className="repo-scan-result" role="status">
          <p className="repo-dedup__empty">No findings available for deduplication.</p>
        </div>
      ) : null}

      {dedup.error ? (
        <div className="repo-scan-error" role="alert">
          Unable to deduplicate repository: {dedup.error}
        </div>
      ) : null}

      {dedup.result ? (
        <div className="repo-scan-result" role="status">
          <div className="repo-scan-result__head">
            <span className="repo-scan-result__title">
              Deduplication completed
            </span>
            <span className="repo-scan-result__repo">{dedup.repoName}</span>
          </div>
          <p className="repo-dedup__summary">
            {dedup.result.total_findings} findings grouped into{" "}
            {dedup.result.unique_findings}{" "}
            {dedup.result.unique_findings === 1
              ? "deduplication group"
              : "deduplication groups"}
            .
          </p>
          <p className="repo-dedup__summary">
            Duplicate occurrences: {dedup.result.duplicate_findings}
          </p>
          <ul className="repo-dedup__groups">
            {dedup.result.groups.map((group) => {
              const related = group.member_finding_ids.filter(
                (id) => id !== group.canonical_finding_id,
              );
              return (
                <li key={group.fingerprint} className="repo-dedup__group">
                  <span className="repo-dedup__type">
                    {group.vulnerability_type}
                  </span>
                  <span
                    className="repo-dedup__fp"
                    title={group.fingerprint}
                  >
                    {group.fingerprint.slice(0, 16)}
                    {"\u2026"}
                  </span>
                  <span className="repo-dedup__count">
                    {group.occurrence_count}{" "}
                    {group.occurrence_count === 1
                      ? "occurrence"
                      : "occurrences"}
                  </span>
                  <Link
                    className="repo-dedup__link"
                    to={`/findings/${group.canonical_finding_id}`}
                  >
                    Canonical: {group.canonical_finding_id}
                  </Link>
                  {related.length > 0 ? (
                    <span className="repo-dedup__members">
                      Related:{" "}
                      {related.map((id) => (
                        <Link key={id} to={`/findings/${id}`}>
                          {id}
                        </Link>
                      ))}
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </div>
      ) : null}

      {loading ? (
        <Card aria-label="Loading repositories">
          <div aria-busy="true">
            <div className="repo-filters">
              {Array.from({ length: 3 }).map((_, index) => (
                <div
                  key={index}
                  className="repo-skeleton-line"
                  style={{ width: 160, height: 32, marginBottom: 20 }}
                />
              ))}
            </div>
            <table className="repo-table">
              <thead>
                <tr>
                  {Array.from({ length: 7 }).map((_, index) => (
                    <th key={index}>
                      <div className="repo-skeleton-line" style={{ height: 10 }} />
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Array.from({ length: 4 }).map((_, index) => (
                  <SkeletonRow key={index} />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : error || list === null ? (
        <Card>
          <div className="repo-error" role="alert" aria-label="Repositories load error">
            <p className="repo-error__text">Unable to load repositories.</p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : !list.has_repositories || repositories.length === 0 ? (
        <Card aria-label="Repository empty state">
          <div className="repo-empty">
            <h2 className="repo-empty__title">No repositories yet</h2>
            <p className="repo-empty__text">
              Repositories will appear after projects are registered.
            </p>
            <div className="repo-empty__cta">
              <Button variant="primary" onClick={openAddRepository}>
                Add Repository
              </Button>
            </div>
          </div>
        </Card>
      ) : (
        <>
          <RepositorySummaryCard
            repositoryCount={summary.repositoryCount}
            findingCount={summary.findingCount}
            assessedCount={summary.assessedCount}
            breachCount={summary.breachCount}
          />
          <Card aria-label="Repository inventory">
            <div className="repo-section">
              <RepositoryFilters
                query={filterValues.q}
                priority={filterValues.priority}
                sla={filterValues.sla}
                options={filterOptions}
                onQueryChange={(value) => patchFilters({ q: value })}
                onPriorityChange={(value) => patchFilters({ priority: value })}
                onSlaChange={(value) => patchFilters({ sla: value })}
              />
            </div>
            {matches.length === 0 ? (
              <p className="repo-empty__text" role="status">
                No repositories match the current filters.
              </p>
            ) : (
              <RepositoryTable
                repositories={matches}
                scanningProjectIds={scanningProjectIds}
                onScan={handleScan}
                deduplicatingProjectIds={deduplicatingProjectIds}
                onDeduplicate={handleDeduplicate}
              />
            )}
          </Card>
        </>
      )}

      {addOpen ? (
        <AddRepositoryModal onClose={() => setAddOpen(false)} onCreated={handleCreated} />
      ) : null}
    </>
  );
}
