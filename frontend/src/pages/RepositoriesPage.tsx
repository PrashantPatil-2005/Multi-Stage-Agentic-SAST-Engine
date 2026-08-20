import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useRepositories } from "../hooks/useRepositories";
import { useDeduplication } from "../hooks/useDeduplication";
import type { RepositorySummary } from "../api/repositories";
import { scanProject, ProjectRequestError } from "../api/projects";
import type { ProjectOut, ScanResponse } from "../api/projects";
import { formatTimestamp } from "../components/risk/riskHelpers";
import { AddRepositoryModal } from "../components/repositories/AddRepositoryModal";
import { DeleteRepositoryModal } from "../components/repositories/DeleteRepositoryModal";
import { PRIORITIES, RepositoryTable } from "../components/repositories/RepositoryTable";
import { RepositoryFilters } from "../components/repositories/RepositoryFilters";
import { RepositorySummary as RepositorySummaryCard } from "../components/repositories/RepositorySummary";
import { ScanHistory } from "../components/repositories/ScanHistory";
import { ReportButton } from "../components/report/ReportButton";
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

// Repository deletion happens inside the confirmation modal, which blocks
// the page; no row delete is ever in flight, so the table always receives
// an empty set.
const NO_DELETES: ReadonlySet<string> = new Set();

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
  const [selectedDedupRun, setSelectedDedupRun] = useState<string>("");
  const [deleteTarget, setDeleteTarget] = useState<RepositorySummary | null>(
    null,
  );
  const [deletedMessage, setDeletedMessage] = useState<string | null>(null);
  const dedup = useDeduplication();

  const scopedProjectId = useMemo(() => {
    const value = searchParams.get("project_id");
    return value !== null && value.trim() !== "" ? value : undefined;
  }, [searchParams]);

  // Reload the inventory once a deduplication run succeeds so the updated
  // findings are reflected in the table. Errors keep the current view.
  const dedupSettled = dedup.result !== null;
  const prevSettledRef = useRef(false);
  useEffect(() => {
    if (dedupSettled && !prevSettledRef.current) {
      reload();
    }
    prevSettledRef.current = dedupSettled;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dedupSettled]);

  const filterValues: FilterValues = useMemo(
    () => ({
      q: searchParams.get("q") ?? "",
      priority: searchParams.get("priority") ?? "",
      sla: searchParams.get("sla") ?? "",
    }),
    [searchParams],
  );

  const repositories = list?.repositories ?? [];
  const scopedRepository =
    scopedProjectId !== undefined
      ? (repositories.find((row) => row.project_id === scopedProjectId) ?? null)
      : null;
  const scopedUnknown =
    scopedProjectId !== undefined &&
    list !== null &&
    !loading &&
    scopedRepository === null;
  const visibleRepositories = scopedRepository
    ? [scopedRepository]
    : repositories;

  const filterOptions = useMemo(() => {
    const priorities = new Set<string>();
    const slaStatuses = new Set<string>();
    for (const row of visibleRepositories) {
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
    return visibleRepositories.filter((row) => {
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
      repositoryCount: visibleRepositories.length,
      findingCount: visibleRepositories.reduce(
        (sum, row) => sum + (row.findings?.total ?? 0),
        0,
      ),
      assessedCount: visibleRepositories.filter((row) => row.risk !== null).length,
      breachCount: visibleRepositories.filter(
        (row) => row.sla !== null && row.sla.breached > 0,
      ).length,
    }),
    [visibleRepositories],
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

  function handleCreated(project: ProjectOut) {
    setAddOpen(false);
    const summary = project.summary;
    const parseFailures =
      summary.parse_failures > 0
        ? `${summary.parse_failures} parse failure${summary.parse_failures === 1 ? "" : "s"}`
        : "0 parse failures";
    setAddedMessage(
      `Repository added and prepared: ${summary.fetched_files} files ` +
        `(${summary.python_files} Python), ${parseFailures}.`,
    );
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
    setSelectedDedupRun("");
    await dedup.begin(projectId, row.name);
    setDeduplicatingProjectIds((prev) => {
      const next = new Set(prev);
      next.delete(projectId);
      return next;
    });
  }

  async function handleConfirmDedup() {
    if (!dedup.context) return;
    const scanRunId = selectedDedupRun;
    if (!scanRunId) return;
    const projectId = dedup.context.projectId;
    setDeduplicatingProjectIds((prev) => new Set(prev).add(projectId));
    setSelectedDedupRun("");
    await dedup.confirmContext(scanRunId);
    setDeduplicatingProjectIds((prev) => {
      const next = new Set(prev);
      next.delete(projectId);
      return next;
    });
  }

  function handleRequestDelete(row: RepositorySummary) {
    setAddedMessage(null);
    setDeletedMessage(null);
    setDeleteTarget(row);
  }

  function handleCancelDelete() {
    setDeleteTarget(null);
  }

  function handleDeleted(repository: RepositorySummary) {
    setDeleteTarget(null);
    setDeletedMessage(`Repository ${repository.name} deleted.`);
    reload();
  }

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Projects and repositories monitored by the security scanner"
        actions={
          <>
            <ReportButton />
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

      {deletedMessage ? (
        <p className="repo-added" role="status">
          {deletedMessage}
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
            <Link
              className="ui-button ui-button--primary"
              to={`/findings?project_id=${encodeURIComponent(lastScan.projectId)}`}
            >
              View Findings
            </Link>
          </div>
        </div>
      ) : null}

      {lastScan ? (
        <ScanHistory projectId={lastScan.projectId} projectName={lastScan.repoName} />
      ) : null}

      {dedup.context ? (
        <div
          className="repo-scan-result"
          role="region"
          aria-label="Deduplication run context"
        >
          <div className="repo-scan-result__head">
            <span className="repo-scan-result__title">
              Deduplicate repository
            </span>
            <span className="repo-scan-result__repo">{dedup.context.repoName}</span>
          </div>
          <p className="repo-dedup__context-note">
            This repository has multiple scan runs. Choose the scan run to
            record this deduplication against.
          </p>
          <div className="repo-dedup__context-controls">
            <label
              className="repo-dedup__context-label"
              htmlFor="dedup-run-context"
            >
              Run context
            </label>
            <select
              id="dedup-run-context"
              className="repo-dedup__context-select"
              aria-label="Scan run context"
              value={selectedDedupRun}
              onChange={(event) => setSelectedDedupRun(event.target.value)}
            >
              <option value="">Select a scan run…</option>
              {dedup.context.runs.map((run) => (
                <option key={run.scan_run_id} value={run.scan_run_id}>
                  {`#${run.scan_run_id.slice(0, 8)} · ${run.status} · ${formatTimestamp(
                    run.started_at,
                  )}`}
                </option>
              ))}
            </select>
            <Button
              variant="primary"
              size="sm"
              disabled={selectedDedupRun === ""}
              onClick={handleConfirmDedup}
            >
              Run deduplication
            </Button>
            <Button variant="secondary" size="sm" onClick={dedup.cancelContext}>
              Cancel
            </Button>
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

      {scopedUnknown ? (
        <Card aria-label="Scoped repository not found">
          <div className="repo-empty">
            <h2 className="repo-empty__title">Repository not found</h2>
            <p className="repo-empty__text">
              No repository matches the requested project{" "}
              <code className="repo-empty__id">{scopedProjectId}</code> in the
              current inventory.
            </p>
            <div className="repo-empty__cta">
              <Link
                className="ui-button ui-button--primary"
                to="/repositories"
              >
                View all repositories
              </Link>
            </div>
          </div>
        </Card>
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
                deletingProjectIds={NO_DELETES}
                onDelete={handleRequestDelete}
              />
            )}
          </Card>
        </>
      )}

      {addOpen ? (
        <AddRepositoryModal onClose={() => setAddOpen(false)} onCreated={handleCreated} />
      ) : null}

      {deleteTarget ? (
        <DeleteRepositoryModal
          repository={deleteTarget}
          onClose={handleCancelDelete}
          onDeleted={handleDeleted}
        />
      ) : null}
    </>
  );
}
