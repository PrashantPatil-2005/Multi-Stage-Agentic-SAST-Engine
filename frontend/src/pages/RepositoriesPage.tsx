import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";

import { useRepositories } from "../hooks/useRepositories";
import { PRIORITIES, RepositoryTable } from "../components/repositories/RepositoryTable";
import { RepositoryFilters } from "../components/repositories/RepositoryFilters";
import { RepositorySummary } from "../components/repositories/RepositorySummary";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "../components/repositories/repositories.css";

interface FilterValues {
  q: string;
  priority: string;
  sla: string;
}

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

  return (
    <>
      <PageHeader
        title="Repositories"
        description="Projects and repositories monitored by the security scanner"
        actions={
          <Button variant="secondary" onClick={reload} disabled={loading}>
            Refresh
          </Button>
        }
      />

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
          </div>
        </Card>
      ) : (
        <>
          <RepositorySummary
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
              <RepositoryTable repositories={matches} />
            )}
          </Card>
        </>
      )}
    </>
  );
}
