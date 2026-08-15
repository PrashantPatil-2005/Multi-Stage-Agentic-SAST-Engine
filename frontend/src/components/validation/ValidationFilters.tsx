import type { ValidationRow } from "../../api/validation";
import { verdictLabel } from "./validationHelpers";

export interface ValidationFilterOptions {
  verdicts: string[];
  severities: string[];
  priorities: string[];
}

export interface ValidationFiltersProps {
  verdict: string;
  severity: string;
  priority: string;
  query: string;
  options: ValidationFilterOptions;
  onVerdictChange: (value: string) => void;
  onSeverityChange: (value: string) => void;
  onPriorityChange: (value: string) => void;
  onQueryChange: (value: string) => void;
}

export function validationFilterOptions(
  rows: ValidationRow[],
  priorities: string[],
): ValidationFilterOptions {
  const verdicts = new Set<string>();
  const severities = new Set<string>();
  for (const row of rows) {
    if (row.verdict !== null) verdicts.add(verdictLabel(row.verdict));
    if (row.severity !== null) severities.add(row.severity);
  }
  return {
    verdicts: [...verdicts].sort(),
    severities: [...severities].sort(),
    priorities: priorities.filter(
      (p) => rows.some((row) => row.priority === p),
    ),
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
    <label className="val-filter">
      <span className="val-filter__label">{label}</span>
      <select
        className="val-filter__control"
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

export function ValidationFilters({
  verdict,
  severity,
  priority,
  query,
  options,
  onVerdictChange,
  onSeverityChange,
  onPriorityChange,
  onQueryChange,
}: ValidationFiltersProps) {
  return (
    <div className="val-filters">
      <FilterSelect
        label="Verdict"
        value={verdict}
        options={options.verdicts}
        allLabel="All verdicts"
        onChange={onVerdictChange}
      />
      <FilterSelect
        label="Severity"
        value={severity}
        options={options.severities}
        allLabel="All severities"
        onChange={onSeverityChange}
      />
      <FilterSelect
        label="Priority"
        value={priority}
        options={options.priorities}
        allLabel="All priorities"
        onChange={onPriorityChange}
      />
      <label className="val-filter val-filter--search">
        <span className="val-filter__label">Search</span>
        <input
          className="val-filter__control"
          type="search"
          value={query}
          aria-label="Search validations"
          placeholder="Finding, vulnerability, repository, file"
          onChange={(event) => onQueryChange(event.target.value)}
        />
      </label>
    </div>
  );
}
