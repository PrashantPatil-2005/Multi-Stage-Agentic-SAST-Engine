import type { ProofRow } from "../../api/proof";
import {
  proofStatusLabel,
  verdictLabel,
} from "../validation/validationHelpers";

export interface ProofFilterOptions {
  statuses: string[];
  priorities: string[];
  severities: string[];
  validations: string[];
}

export interface ProofFiltersProps {
  status: string;
  priority: string;
  severity: string;
  validation: string;
  query: string;
  options: ProofFilterOptions;
  onStatusChange: (value: string) => void;
  onPriorityChange: (value: string) => void;
  onSeverityChange: (value: string) => void;
  onValidationChange: (value: string) => void;
  onQueryChange: (value: string) => void;
}

export function proofFilterOptions(
  rows: ProofRow[],
  priorities: string[],
): ProofFilterOptions {
  const statuses = new Set<string>();
  const severities = new Set<string>();
  const validations = new Set<string>();
  for (const row of rows) {
    statuses.add(proofStatusLabel(row.status));
    if (row.severity !== null) severities.add(row.severity);
    if (row.validation !== null) validations.add(verdictLabel(row.validation));
  }
  return {
    statuses: [...statuses].sort(),
    priorities: priorities.filter(
      (p) => rows.some((row) => row.priority === p),
    ),
    severities: [...severities].sort(),
    validations: [...validations].sort(),
  };
}

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
    <label className="pf-filter">
      <span className="pf-filter__label">{label}</span>
      <select
        className="pf-filter__control"
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

export function ProofFilters({
  status,
  priority,
  severity,
  validation,
  query,
  options,
  onStatusChange,
  onPriorityChange,
  onSeverityChange,
  onValidationChange,
  onQueryChange,
}: ProofFiltersProps) {
  return (
    <div className="pf-filters">
      <FilterSelect
        label="Proof Status"
        value={status}
        options={options.statuses}
        allLabel="All proof statuses"
        onChange={onStatusChange}
      />
      <FilterSelect
        label="Priority"
        value={priority}
        options={options.priorities}
        allLabel="All priorities"
        onChange={onPriorityChange}
      />
      <FilterSelect
        label="Severity"
        value={severity}
        options={options.severities}
        allLabel="All severities"
        onChange={onSeverityChange}
      />
      <FilterSelect
        label="Validation Verdict"
        value={validation}
        options={options.validations}
        allLabel="All validation verdicts"
        onChange={onValidationChange}
      />
      <label className="pf-filter pf-filter--search">
        <span className="pf-filter__label">Search</span>
        <input
          className="pf-filter__control"
          type="search"
          value={query}
          aria-label="Search proofs"
          placeholder="Finding, vulnerability, repository, file"
          onChange={(event) => onQueryChange(event.target.value)}
        />
      </label>
    </div>
  );
}
