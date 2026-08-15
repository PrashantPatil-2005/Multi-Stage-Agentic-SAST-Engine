import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";

import type { RiskSummary } from "../api/risk";
import { EscalationTimeline } from "../components/risk/EscalationTimeline";
import { HighestRiskFindings } from "../components/risk/HighestRiskFindings";
import { PriorityDistribution } from "../components/risk/PriorityDistribution";
import { RiskDistribution } from "../components/risk/RiskDistribution";
import { RiskMetricCards } from "../components/risk/RiskMetricCards";
import { SlaBreaches } from "../components/risk/SlaBreaches";
import { SlaOverview } from "../components/risk/SlaOverview";
import { SlaTable } from "../components/risk/SlaTable";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { useRiskSummary } from "../hooks/useRiskSummary";
import "../components/risk/risk.css";

const PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4"];

function FilterSelect({
  label,
  value,
  options,
  allLabel,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  allLabel: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="risk-filter">
      <span className="risk-filter__label">{label}</span>
      <select
        className="risk-filter__control"
        value={value}
        aria-label={label}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">{allLabel}</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

function KpiSkeleton() {
  return <Card><div className="risk-skeleton risk-skeleton--kpi" aria-hidden="true" /></Card>;
}

function ChartSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="risk-skeleton risk-skeleton--line" aria-hidden="true" />
      <div className="risk-skeleton risk-skeleton--bar" aria-hidden="true" />
      <div className="risk-skeleton risk-skeleton--bar" aria-hidden="true" />
      <div className="risk-skeleton risk-skeleton--bar" style={{ width: "70%" }} aria-hidden="true" />
    </Card>
  );
}

function TableSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="risk-skeleton risk-skeleton--table" aria-hidden="true" />
    </Card>
  );
}

export function RiskPage() {
  const { summary, loading, error, reload } = useRiskSummary();
  const [searchParams, setSearchParams] = useSearchParams();

  const priorityFilter = searchParams.get("priority") ?? "";
  const severityFilter = searchParams.get("severity") ?? "";
  const slaFilter = searchParams.get("sla") ?? "";
  const levelFilter = searchParams.get("level") ?? "";

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
    if (data === null) return { priorities: [], severities: [], slaStatuses: [], levels: [] };
    const priorities = new Set<string>();
    const severities = new Set<string>();
    const slaStatuses = new Set<string>();
    const levels = new Set<string>();
    for (const row of data.highest_risk_findings) {
      priorities.add(row.priority);
      severities.add(row.severity);
      slaStatuses.add(row.sla);
    }
    for (const row of data.active_slas) priorities.add(row.priority);
    for (const row of data.breaches) priorities.add(row.priority);
    for (const row of data.escalations) {
      if (row.priority !== null) priorities.add(row.priority);
      levels.add(String(row.new_level));
    }
    return {
      priorities: PRIORITY_ORDER.filter((p) => priorities.has(p)),
      severities: [...severities].sort(),
      slaStatuses: [...slaStatuses].sort(),
      levels: [...levels].sort((a, b) => Number(a) - Number(b)),
    };
  }, [summary]);

  const matchesFinding = (row: { priority: string; severity: string; sla: string }) => {
    if (priorityFilter !== "" && row.priority !== priorityFilter) return false;
    if (severityFilter !== "" && row.severity !== severityFilter) return false;
    if (slaFilter !== "" && row.sla !== slaFilter) return false;
    return true;
  };

  const matchesSlaRow = (row: { priority: string; status: string }) => {
    if (priorityFilter !== "" && row.priority !== priorityFilter) return false;
    if (slaFilter !== "" && row.status !== slaFilter) return false;
    return true;
  };

  const matchesEscalation = (row: { priority: string | null; new_level: number }) => {
    if (priorityFilter !== "" && row.priority !== priorityFilter) return false;
    if (levelFilter !== "" && String(row.new_level) !== levelFilter) return false;
    return true;
  };

  return (
    <div className="risk-page">
      <PageHeader
        title="Risk & SLA"
        description="Prioritize security findings and track remediation deadlines"
        actions={
          <Button variant="secondary" onClick={reload}>
            Refresh
          </Button>
        }
      />

      {loading ? (
        <div aria-busy="true">
          <div className="risk-kpi-grid">
            {[0, 1, 2, 3, 4, 5].map((index) => (
              <KpiSkeleton key={index} />
            ))}
          </div>
          <div className="risk-layout">
            <ChartSkeleton title="Priority Distribution" />
            <ChartSkeleton title="Risk Distribution" />
          </div>
          <TableSkeleton title="Highest Risk Findings" />
          <div className="risk-layout">
            <ChartSkeleton title="SLA Overview" />
            <TableSkeleton title="Active SLAs" />
          </div>
          <TableSkeleton title="SLA Breaches" />
          <TableSkeleton title="Escalation Activity" />
        </div>
      ) : error || summary === null ? (
        <Card>
          <div className="dash-error" role="alert" aria-label="Risk data error">
            <p className="dash-error__text">Unable to load risk data.</p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : !summary.has_findings && !summary.kpis.total_assessments.available ? (
        <Card>
          <div className="risk-empty">
            <h2 className="risk-empty__title">No risk data available</h2>
            <p className="risk-empty__text">
              Risk information will appear after findings have been scanned and
              risk-assessed.
            </p>
          </div>
        </Card>
      ) : (
        <RiskContent
          summary={summary}
          filters={{
            priority: priorityFilter,
            severity: severityFilter,
            sla: slaFilter,
            level: levelFilter,
          }}
          options={filterOptions}
          setFilter={setFilter}
          matchesFinding={matchesFinding}
          matchesSlaRow={matchesSlaRow}
          matchesEscalation={matchesEscalation}
        />
      )}
    </div>
  );
}

interface RiskContentProps {
  summary: RiskSummary;
  filters: { priority: string; severity: string; sla: string; level: string };
  options: { priorities: string[]; severities: string[]; slaStatuses: string[]; levels: string[] };
  setFilter: (key: string, value: string) => void;
  matchesFinding: (row: { priority: string; severity: string; sla: string }) => boolean;
  matchesSlaRow: (row: { priority: string; status: string }) => boolean;
  matchesEscalation: (row: { priority: string | null; new_level: number }) => boolean;
}

function RiskContent({
  summary,
  filters,
  options,
  setFilter,
  matchesFinding,
  matchesSlaRow,
  matchesEscalation,
}: RiskContentProps) {
  const findings = summary.highest_risk_findings.filter(matchesFinding);
  const activeSl = summary.active_slas.filter(matchesSlaRow);
  const breaches = summary.breaches.filter(matchesSlaRow);
  const escalations = summary.escalations.filter(matchesEscalation);

  return (
    <>
      <div className="risk-filters">
        <FilterSelect
          label="Priority"
          value={filters.priority}
          options={options.priorities}
          allLabel="All priorities"
          onChange={(value) => setFilter("priority", value)}
        />
        <FilterSelect
          label="Severity"
          value={filters.severity}
          options={options.severities}
          allLabel="All severities"
          onChange={(value) => setFilter("severity", value)}
        />
        <FilterSelect
          label="SLA Status"
          value={filters.sla}
          options={options.slaStatuses}
          allLabel="All SLA statuses"
          onChange={(value) => setFilter("sla", value)}
        />
        <FilterSelect
          label="Escalation Level"
          value={filters.level}
          options={options.levels}
          allLabel="All escalation levels"
          onChange={(value) => setFilter("level", value)}
        />
      </div>

      <RiskMetricCards kpis={summary.kpis} />

      <div className="risk-layout">
        <PriorityDistribution buckets={summary.priority_distribution} />
        <RiskDistribution buckets={summary.risk_distribution} />
      </div>

      <div className="risk-layout">
        <SlaOverview overview={summary.sla_overview} />
        <SlaTable rows={activeSl} />
      </div>

      <div className="risk-section">
        <HighestRiskFindings rows={findings} />
      </div>

      <div className="risk-section">
        <SlaBreaches rows={breaches} />
      </div>

      <div className="risk-section">
        <EscalationTimeline rows={escalations} />
      </div>
    </>
  );
}
