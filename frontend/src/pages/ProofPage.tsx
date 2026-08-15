import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

import type { ProofSummary as ProofSummaryData } from "../api/proof";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import {
  proofFilterOptions,
  ProofFilters,
} from "../components/proof/ProofFilters";
import { ProofMetricCards } from "../components/proof/ProofMetricCards";
import { ProofTable } from "../components/proof/ProofTable";
import { proofStatusLabel } from "../components/proof/proofHelpers";
import { verdictLabel } from "../components/validation/validationHelpers";
import { useProof } from "../hooks/useProof";
import "../components/proof/proof.css";

const PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4"];

function KpiSkeleton() {
  return <Card><div className="pf-skeleton pf-skeleton--kpi" aria-hidden="true" /></Card>;
}

function TableSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="pf-skeleton pf-skeleton--table" aria-hidden="true" />
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

export function ProofPage() {
  const { summary, loading, error, reload } = useProof();
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState("");

  const statusFilter = searchParams.get("status") ?? "";
  const priorityFilter = searchParams.get("priority") ?? "";
  const severityFilter = searchParams.get("severity") ?? "";
  const validationFilter = searchParams.get("validation") ?? "";

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
    if (data === null) return { statuses: [], priorities: [], severities: [], validations: [] };
    return proofFilterOptions(data.records, PRIORITY_ORDER);
  }, [summary]);

  const matches = (row: {
    status: string;
    priority: string | null;
    severity: string | null;
    validation: string | null;
    finding_id: string;
    vulnerability_type: string | null;
    repository: string | null;
    file: string | null;
  }) => {
    if (statusFilter !== "" && proofStatusLabel(row.status) !== statusFilter) {
      return false;
    }
    if (priorityFilter !== "" && row.priority !== priorityFilter) return false;
    if (severityFilter !== "" && row.severity !== severityFilter) return false;
    if (
      validationFilter !== "" &&
      verdictLabel(row.validation) !== validationFilter
    ) {
      return false;
    }
    return matchesQuery(row, query.trim());
  };

  return (
    <div className="pf-page">
      <PageHeader
        title="Proof"
        description="Sandboxed verification results for validated findings"
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      {loading ? (
        <div aria-busy="true">
          <div className="pf-kpi-grid">
            {[0, 1, 2, 3, 4].map((index) => (
              <KpiSkeleton key={index} />
            ))}
          </div>
          <TableSkeleton title="Proof Results" />
        </div>
      ) : error || summary === null ? (
        <Card>
          <div className="dash-error" role="alert" aria-label="Proof data error">
            <p className="dash-error__text">Unable to load proof results.</p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : !summary.has_findings && !summary.kpis.total.available ? (
        <Card>
          <div className="risk-empty">
            <h2 className="risk-empty__title">No proof results</h2>
            <p className="risk-empty__text">
              Proof results will appear after the proof stage processes
              validated findings.
            </p>
          </div>
        </Card>
      ) : (
        <ProofContent
          summary={summary}
          filters={{
            status: statusFilter,
            priority: priorityFilter,
            severity: severityFilter,
            validation: validationFilter,
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

interface ProofContentProps {
  summary: ProofSummaryData;
  filters: {
    status: string;
    priority: string;
    severity: string;
    validation: string;
  };
  query: string;
  options: {
    statuses: string[];
    priorities: string[];
    severities: string[];
    validations: string[];
  };
  setFilter: (key: string, value: string) => void;
  setQuery: (value: string) => void;
  matches: (row: {
    status: string;
    priority: string | null;
    severity: string | null;
    validation: string | null;
    finding_id: string;
    vulnerability_type: string | null;
    repository: string | null;
    file: string | null;
  }) => boolean;
}

function ProofContent({
  summary,
  filters,
  query,
  options,
  setFilter,
  setQuery,
  matches,
}: ProofContentProps) {
  const records = summary.records.filter(matches);

  return (
    <>
      <ProofFilters
        status={filters.status}
        priority={filters.priority}
        severity={filters.severity}
        validation={filters.validation}
        query={query}
        options={options}
        onStatusChange={(value) => setFilter("status", value)}
        onPriorityChange={(value) => setFilter("priority", value)}
        onSeverityChange={(value) => setFilter("severity", value)}
        onValidationChange={(value) => setFilter("validation", value)}
        onQueryChange={setQuery}
      />

      <ProofMetricCards kpis={summary.kpis} />

      <div className="pf-section">
        <ProofTable rows={records} />
      </div>
    </>
  );
}
