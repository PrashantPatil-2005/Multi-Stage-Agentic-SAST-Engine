import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import type { ValidationSummary } from "../api/validation";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import {
  ValidationFilters,
  validationFilterOptions,
} from "../components/validation/ValidationFilters";
import { ValidationMetricCards } from "../components/validation/ValidationMetricCards";
import { ValidationTable } from "../components/validation/ValidationTable";
import { verdictLabel } from "../components/validation/validationHelpers";
import { useValidation } from "../hooks/useValidation";
import "../components/validation/validation.css";

const PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4"];

function KpiSkeleton() {
  return <Card><div className="val-skeleton val-skeleton--kpi" aria-hidden="true" /></Card>;
}

function TableSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="val-skeleton val-skeleton--table" aria-hidden="true" />
    </Card>
  );
}

function matchesQuery(row: {
  finding_id: string;
  vulnerability_type: string | null;
  repository: string | null;
  file: string | null;
}, query: string): boolean {
  if (query === "") return true;
  const needle = query.toLowerCase();
  const haystack = [
    row.finding_id,
    row.vulnerability_type,
    row.repository,
    row.file,
  ]
    .filter((value): value is string => value !== null)
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

export function ValidationPage() {
  const { summary, loading, error, reload } = useValidation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState("");

  const verdictFilter = searchParams.get("verdict") ?? "";
  const severityFilter = searchParams.get("severity") ?? "";
  const priorityFilter = searchParams.get("priority") ?? "";

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams);
    if (value === "") {
      next.delete(key);
    } else {
      next.set(key, value);
    }
    setSearchParams(next, { replace: true });
  };

  const filterOptions = useMemo(() => {
    const data = summary;
    if (data === null) return { verdicts: [], severities: [], priorities: [] };
    return validationFilterOptions(data.records, PRIORITY_ORDER);
  }, [summary]);

  const matches = (row: {
    verdict: string | null;
    severity: string | null;
    priority: string | null;
    finding_id: string;
    vulnerability_type: string | null;
    repository: string | null;
    file: string | null;
  }) => {
    if (verdictFilter !== "" && verdictLabel(row.verdict) !== verdictFilter) {
      return false;
    }
    if (severityFilter !== "" && row.severity !== severityFilter) return false;
    if (priorityFilter !== "" && row.priority !== priorityFilter) return false;
    return matchesQuery(row, query.trim());
  };

  return (
    <div className="val-page">
      <PageHeader
        title="Validation"
        description="LLM-assisted validation of detected security findings"
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      {loading ? (
        <div aria-busy="true">
          <div className="val-kpi-grid">
            {[0, 1, 2, 3, 4].map((index) => (
              <KpiSkeleton key={index} />
            ))}
          </div>
          <TableSkeleton title="Validation Results" />
        </div>
      ) : error || summary === null ? (
        <Card>
          <div className="dash-error" role="alert" aria-label="Validation data error">
            <p className="dash-error__text">Unable to load validation results.</p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : !summary.has_findings && !summary.kpis.total_validations.available ? (
        <Card>
          <div className="risk-empty">
            <h2 className="risk-empty__title">No validation results</h2>
            <p className="risk-empty__text">
              Validation results will appear after findings have passed through
              the validation stage.
            </p>
          </div>
        </Card>
      ) : (
        <ValidationContent
          summary={summary}
          filters={{
            verdict: verdictFilter,
            severity: severityFilter,
            priority: priorityFilter,
          }}
          query={query}
          options={filterOptions}
          setFilter={setFilter}
          setQuery={setQuery}
          matches={matches}
        />
      )}
    </div>
  );
}

interface ValidationContentProps {
  summary: ValidationSummary;
  filters: { verdict: string; severity: string; priority: string };
  query: string;
  options: { verdicts: string[]; severities: string[]; priorities: string[] };
  setFilter: (key: string, value: string) => void;
  setQuery: (value: string) => void;
  matches: (row: {
    verdict: string | null;
    severity: string | null;
    priority: string | null;
    finding_id: string;
    vulnerability_type: string | null;
    repository: string | null;
    file: string | null;
  }) => boolean;
}

function ValidationContent({
  summary,
  filters,
  query,
  options,
  setFilter,
  setQuery,
  matches,
}: ValidationContentProps) {
  const records = summary.records.filter(matches);

  return (
    <>
      <ValidationFilters
        verdict={filters.verdict}
        severity={filters.severity}
        priority={filters.priority}
        query={query}
        options={options}
        onVerdictChange={(value) => setFilter("verdict", value)}
        onSeverityChange={(value) => setFilter("severity", value)}
        onPriorityChange={(value) => setFilter("priority", value)}
        onQueryChange={setQuery}
      />

      <ValidationMetricCards kpis={summary.kpis} />

      <div className="val-section">
        <ValidationTable rows={records} />
      </div>
    </>
  );
}
