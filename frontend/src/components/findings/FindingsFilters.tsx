import "./findings.css";

export interface FilterValues {
  severity: string;
  priority: string;
  vulnerability: string;
  validation: string;
  proof: string;
  sla: string;
  approval: string;
  q: string;
}

export const ALL = "ALL";

export interface AvailableFilters {
  severity: string[];
  priority: string[];
  vulnerability: string[];
  validation: string[];
  proof: string[];
  sla: string[];
  approval: string[];
}

export interface FindingsFiltersProps {
  values: FilterValues;
  available: AvailableFilters;
  onChange: (patch: Partial<FilterValues>) => void;
}

export const VALIDATION_LABELS: Record<string, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  uncertain: "Uncertain",
  not_validated: "Not validated",
};

export const PROOF_LABELS: Record<string, string> = {
  verified: "Verified",
  not_verified: "Not verified",
  blocked: "Blocked",
  error: "Error",
  no_proof: "No proof",
};

export const SLA_LABELS: Record<string, string> = {
  active: "Active",
  breached: "Breached",
  resolved: "Resolved",
  no_sla: "No SLA",
};

export const APPROVAL_LABELS: Record<string, string> = {
  approved: "Approved",
  rejected: "Rejected",
  pending: "Pending",
  changes_requested: "Changes requested",
  no_approval: "No approval",
};

interface SelectFieldProps {
  label: string;
  value: string;
  options: string[];
  optionLabel: (value: string) => string;
  onChange: (value: string) => void;
}

function SelectField({
  label,
  value,
  options,
  optionLabel,
  onChange,
}: SelectFieldProps) {
  const visibleOptions = options.includes(value) ? options : [value, ...options];
  return (
    <label className="f-toolbar__field">
      <span className="f-toolbar__label">{label}</span>
      <select
        className="f-toolbar__select"
        aria-label={
          label.toLowerCase() === "sla"
            ? "Filter by SLA"
            : `Filter by ${label.toLowerCase()}`
        }
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value={ALL}>All</option>
        {visibleOptions.map((option) => (
          <option key={option} value={option}>
            {optionLabel(option)}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FindingsFilters({
  values,
  available,
  onChange,
}: FindingsFiltersProps) {
  return (
    <div className="f-toolbar" role="search">
      <div className="f-toolbar__row">
        <label className="f-toolbar__search">
          <span className="f-toolbar__label">Search</span>
          <input
            className="f-toolbar__search-input"
            type="search"
            placeholder="ID, vulnerability, repository, file, source or sink"
            aria-label="Search findings"
            value={values.q}
            onChange={(event) => onChange({ q: event.target.value })}
          />
        </label>
        <SelectField
          label="Severity"
          value={values.severity}
          options={available.severity}
          optionLabel={(v) => v}
          onChange={(severity) => onChange({ severity })}
        />
        <SelectField
          label="Priority"
          value={values.priority}
          options={available.priority}
          optionLabel={(v) => v}
          onChange={(priority) => onChange({ priority })}
        />
        <SelectField
          label="Vulnerability"
          value={values.vulnerability}
          options={available.vulnerability}
          optionLabel={(v) => v}
          onChange={(vulnerability) => onChange({ vulnerability })}
        />
      </div>
      <div className="f-toolbar__row">
        <SelectField
          label="Validation"
          value={values.validation}
          options={available.validation}
          optionLabel={(v) => VALIDATION_LABELS[v] ?? v}
          onChange={(validation) => onChange({ validation })}
        />
        <SelectField
          label="Proof"
          value={values.proof}
          options={available.proof}
          optionLabel={(v) => PROOF_LABELS[v] ?? v}
          onChange={(proof) => onChange({ proof })}
        />
        <SelectField
          label="SLA"
          value={values.sla}
          options={available.sla}
          optionLabel={(v) => SLA_LABELS[v] ?? v}
          onChange={(sla) => onChange({ sla })}
        />
        <SelectField
          label="Approval"
          value={values.approval}
          options={available.approval}
          optionLabel={(v) => APPROVAL_LABELS[v] ?? v}
          onChange={(approval) => onChange({ approval })}
        />
      </div>
    </div>
  );
}