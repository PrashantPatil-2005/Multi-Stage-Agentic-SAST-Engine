import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { useFindings } from "../hooks/useFindings";
import { useProject } from "../hooks/useProject";
import { FindingsEmptyState } from "../components/findings/FindingsEmptyState";
import {
  ALL,
  FindingsFilters,
  type FilterValues,
} from "../components/findings/FindingsFilters";
import {
  FindingsTable,
  type SortKey,
  type SortState,
} from "../components/findings/FindingsTable";
import {
  formatSeverity,
  priorityRank,
  severityRank,
  vulnLabel,
} from "../components/findings/findingsHelpers";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "../components/findings/findings.css";

const SLA_RANK: Record<string, number> = {
  breached: 0,
  active: 1,
  resolved: 2,
  none: 3,
  not_applicable: 4,
};

function SkeletonRow() {
  return (
    <tr aria-hidden="true">
      {Array.from({ length: 9 }).map((_, index) => (
        <td key={index}>
          <div className="f-skeleton" style={{ height: 14 }} />
        </td>
      ))}
    </tr>
  );
}

function SkeletonCard() {
  return (
    <li aria-hidden="true" className="f-card">
      <div className="f-skeleton" style={{ height: 16 }} />
      <div
        className="f-skeleton"
        style={{ height: 12, marginTop: 10, width: "60%" }}
      />
    </li>
  );
}

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const projectId = useMemo(() => {
    const value = searchParams.get("project_id");
    return value !== null && value.trim() !== "" ? value : undefined;
  }, [searchParams]);
  const { findings, loading, error, notFound, reload } = useFindings(projectId);
  const { project } = useProject(projectId);
  const [sort, setSort] = useState<SortState>({ key: "priority", dir: "asc" });

  const filterValues: FilterValues = useMemo(
    () => ({
      severity: searchParams.get("severity") ?? ALL,
      priority: searchParams.get("priority") ?? ALL,
      vulnerability: searchParams.get("vulnerability") ?? ALL,
      validation: searchParams.get("validation") ?? ALL,
      proof: searchParams.get("proof") ?? ALL,
      sla: searchParams.get("sla") ?? ALL,
      approval: searchParams.get("approval") ?? ALL,
      q: searchParams.get("q") ?? "",
    }),
    [searchParams],
  );

  const available = useMemo(() => {
    const severity = new Set<string>();
    const priority = new Set<string>();
    const vulnerability = new Set<string>();
    const validation = new Set<string>();
    const proof = new Set<string>();
    const sla = new Set<string>();
    const approval = new Set<string>();
    let hasUnvalidated = false;
    let hasNoProof = false;
    let hasNoSla = false;
    let hasNoApproval = false;
    for (const finding of findings) {
      severity.add(formatSeverity(finding.severity));
      if (finding.priority !== null) priority.add(finding.priority);
      vulnerability.add(finding.vulnerability_type);
      if (finding.verdict !== null) {
        validation.add(finding.verdict);
      } else {
        hasUnvalidated = true;
      }
      if (finding.proof_status !== null) {
        proof.add(finding.proof_status);
      } else {
        hasNoProof = true;
      }
      if (
        finding.sla.status === "none" ||
        finding.sla.status === "not_applicable"
      ) {
        hasNoSla = true;
      } else {
        sla.add(finding.sla.status);
      }
      if (finding.approval_status !== null) {
        approval.add(finding.approval_status);
      } else {
        hasNoApproval = true;
      }
    }
    return {
      severity: [...severity].sort((a, b) => severityRank(a) - severityRank(b)),
      priority: [...priority].sort((a, b) => priorityRank(a) - priorityRank(b)),
      vulnerability: [...vulnerability].sort(),
      validation: [...validation].sort().concat(hasUnvalidated ? ["not_validated"] : []),
      proof: [...proof].sort().concat(hasNoProof ? ["no_proof"] : []),
      sla: [...sla].sort().concat(hasNoSla ? ["no_sla"] : []),
      approval: [...approval].sort().concat(hasNoApproval ? ["no_approval"] : []),
    };
  }, [findings]);

  const matches = useMemo(() => {
    const q = filterValues.q.trim().toLowerCase();
    return findings.filter((finding) => {
      if (
        filterValues.severity !== ALL &&
        formatSeverity(finding.severity) !== filterValues.severity
      ) {
        return false;
      }
      if (filterValues.priority !== ALL && finding.priority !== filterValues.priority) {
        return false;
      }
      if (
        filterValues.vulnerability !== ALL &&
        finding.vulnerability_type !== filterValues.vulnerability
      ) {
        return false;
      }
      if (filterValues.validation === "not_validated") {
        if (finding.verdict !== null) return false;
      } else if (
        filterValues.validation !== ALL &&
        finding.verdict !== filterValues.validation
      ) {
        return false;
      }
      if (filterValues.proof === "no_proof") {
        if (finding.proof_status !== null) return false;
      } else if (
        filterValues.proof !== ALL &&
        finding.proof_status !== filterValues.proof
      ) {
        return false;
      }
      if (filterValues.sla === "no_sla") {
        if (
          finding.sla.status !== "none" &&
          finding.sla.status !== "not_applicable"
        ) {
          return false;
        }
      } else if (
        filterValues.sla !== ALL &&
        finding.sla.status !== filterValues.sla
      ) {
        return false;
      }
      if (filterValues.approval === "no_approval") {
        if (finding.approval_status !== null) return false;
      } else if (
        filterValues.approval !== ALL &&
        finding.approval_status !== filterValues.approval
      ) {
        return false;
      }
      if (q) {
        const haystack = [
          finding.finding_id,
          finding.vulnerability_type,
          finding.repository ?? "",
          finding.file,
          finding.source_snippet,
          finding.sink_snippet,
          finding.source_kind,
          finding.sink_kind,
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [findings, filterValues]);

  const sorted = useMemo(() => {
    const dir = sort.dir === "asc" ? 1 : -1;
    return [...matches].sort((a, b) => {
      let cmp = 0;
      switch (sort.key) {
        case "priority": {
          if (a.priority === null && b.priority === null) cmp = 0;
          else if (a.priority === null) cmp = 1;
          else if (b.priority === null) cmp = -1;
          else cmp = (priorityRank(a.priority) - priorityRank(b.priority)) * dir;
          break;
        }
        case "severity":
          cmp = (severityRank(a.severity) - severityRank(b.severity)) * dir;
          break;
        case "confidence": {
          if (a.validation_confidence === null && b.validation_confidence === null) {
            cmp = 0;
          } else if (a.validation_confidence === null) {
            cmp = 1;
          } else if (b.validation_confidence === null) {
            cmp = -1;
          } else {
            cmp = (a.validation_confidence - b.validation_confidence) * dir;
          }
          break;
        }
        case "sla":
          cmp = (SLA_RANK[a.sla.status] - SLA_RANK[b.sla.status]) * dir;
          break;
        case "repository": {
          if (a.repository === null && b.repository === null) cmp = 0;
          else if (a.repository === null) cmp = 1;
          else if (b.repository === null) cmp = -1;
          else {
            cmp =
              a.repository.toLowerCase().localeCompare(
                b.repository.toLowerCase(),
              ) * dir;
          }
          break;
        }
        case "file":
          cmp = a.file.toLowerCase().localeCompare(b.file.toLowerCase()) * dir;
          break;
      }
      if (cmp === 0) cmp = severityRank(a.severity) - severityRank(b.severity);
      if (cmp === 0) {
        cmp = vulnLabel(a.vulnerability_type).localeCompare(
          vulnLabel(b.vulnerability_type),
        );
      }
      if (cmp === 0) cmp = a.finding_id.localeCompare(b.finding_id);
      return cmp;
    });
  }, [matches, sort]);

  function patchFilters(patch: Partial<FilterValues>) {
    const next = new URLSearchParams(searchParams);
    (Object.entries(patch) as Array<[keyof FilterValues, string]>).forEach(
      ([key, value]) => {
        if (value === ALL || value === "") {
          next.delete(key);
        } else {
          next.set(key, value);
        }
      },
    );
    setSearchParams(next, { replace: true });
  }

  function handleSortChange(key: SortKey) {
    setSort((current) =>
      current.key === key
        ? { key, dir: current.dir === "asc" ? "desc" : "asc" }
        : { key, dir: key === "confidence" ? "desc" : "asc" },
    );
  }

  return (
    <>
      <PageHeader
        title="Security Findings"
        description="Detected security issues across analyzed repositories"
        actions={
          <Button variant="secondary" onClick={reload} disabled={loading}>
            Refresh
          </Button>
        }
      />

      {projectId !== undefined && !loading && !error && !notFound ? (
        <div className="f-scope" role="status">
          <span className="f-scope__label">Repository:</span>
          <span className="f-scope__name">
            {project ? project.name : "Loading\u2026"}
          </span>
          <Link className="f-scope__clear" to="/findings">
            Clear filter
          </Link>
        </div>
      ) : null}

      {notFound ? (
        <Card>
          <div className="f-error" role="alert" aria-label="Repository not found">
            <p className="f-error__text">Repository not found.</p>
            <Link
              className="ui-button ui-button--secondary ui-button--md"
              to="/findings"
            >
              View all findings
            </Link>
          </div>
        </Card>
      ) : !loading && !error ? (
        <Card>
          <div className="f-toolbar">
            <FindingsFilters
              values={filterValues}
              available={available}
              onChange={patchFilters}
            />
          </div>
          {sorted.length === 0 ? (
            projectId !== undefined ? (
              <p className="f-scope-empty" role="status">
                0 findings for this repository.
              </p>
            ) : (
              <FindingsEmptyState filtered={findings.length > 0} />
            )
          ) : (
            <FindingsTable
              findings={sorted}
              sort={sort}
              onSortChange={handleSortChange}
            />
          )}
        </Card>
      ) : error ? (
        <Card>
          <div className="f-error" role="alert" aria-label="Findings load error">
            <p className="f-error__text">Unable to load findings.</p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : (
        <Card>
          <div aria-busy="true">
            <div className="f-table-wrap">
              <table className="f-table">
                <thead>
                  <tr>
                    {Array.from({ length: 9 }).map((_, index) => (
                      <th key={index}>
                        <div className="f-skeleton" style={{ height: 12 }} />
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Array.from({ length: 6 }).map((_, index) => (
                    <SkeletonRow key={index} />
                  ))}
                </tbody>
              </table>
            </div>
            <ul className="f-cards">
              {Array.from({ length: 4 }).map((_, index) => (
                <SkeletonCard key={index} />
              ))}
            </ul>
          </div>
        </Card>
      )}
    </>
  );
}