export interface RepositoryFilterOptions {
  priorities: string[];
  slaStatuses: string[];
}

export interface RepositoryFiltersProps {
  query: string;
  priority: string;
  sla: string;
  options: RepositoryFilterOptions;
  onQueryChange: (value: string) => void;
  onPriorityChange: (value: string) => void;
  onSlaChange: (value: string) => void;
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
    <label className="repo-filter">
      <span className="repo-filter__label">{label}</span>
      <select
        className="repo-filter__control"
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

export function RepositoryFilters({
  query,
  priority,
  sla,
  options,
  onQueryChange,
  onPriorityChange,
  onSlaChange,
}: RepositoryFiltersProps) {
  return (
    <div className="repo-filters">
      <FilterSelect
        label="Priority"
        value={priority}
        options={options.priorities}
        allLabel="All priorities"
        onChange={onPriorityChange}
      />
      <FilterSelect
        label="SLA"
        value={sla}
        options={options.slaStatuses}
        allLabel="All SLA statuses"
        onChange={onSlaChange}
      />
      <label className="repo-filter repo-filter--search">
        <span className="repo-filter__label">Search</span>
        <input
          className="repo-filter__control"
          type="search"
          value={query}
          aria-label="Search repositories"
          placeholder="Name, project ID, location"
          onChange={(event) => onQueryChange(event.target.value)}
        />
      </label>
    </div>
  );
}
