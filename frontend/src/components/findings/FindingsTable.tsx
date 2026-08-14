import type { FindingListItem } from "../../api/findings";
import { FindingCard } from "./FindingCard";
import { FindingRow } from "./FindingRow";
import "./findings.css";

export type SortKey =
  | "priority"
  | "severity"
  | "confidence"
  | "sla"
  | "repository"
  | "file";

export type SortDir = "asc" | "desc";

export interface SortState {
  key: SortKey;
  dir: SortDir;
}

const SORTABLE: Array<{ key: SortKey; label: string }> = [
  { key: "priority", label: "Priority" },
  { key: "severity", label: "Severity" },
  { key: "confidence", label: "Confidence" },
  { key: "sla", label: "SLA" },
  { key: "repository", label: "Repository" },
  { key: "file", label: "File" },
];

export interface FindingsTableProps {
  findings: FindingListItem[];
  sort: SortState;
  onSortChange: (key: SortKey) => void;
}

export function FindingsTable({
  findings,
  sort,
  onSortChange,
}: FindingsTableProps) {
  return (
    <>
      <div className="f-table-wrap">
        <table className="f-table">
          <caption className="f-table__caption">
            Security findings ({findings.length})
          </caption>
          <thead>
            <tr>
              {SORTABLE.map(({ key, label }) => (
                <th
                  key={key}
                  aria-sort={
                    sort.key === key
                      ? sort.dir === "asc"
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                >
                  <button
                    type="button"
                    className="f-table__sort"
                    onClick={() => onSortChange(key)}
                  >
                    {label}
                    <span className="f-table__sort-caret" aria-hidden="true">
                      {sort.key === key ? (sort.dir === "asc" ? "▲" : "▼") : ""}
                    </span>
                  </button>
                </th>
              ))}
              <th>Vulnerability</th>
              <th className="f-col-flow">Source → Sink</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <FindingRow key={finding.finding_id} finding={finding} />
            ))}
          </tbody>
        </table>
      </div>

      <ul className="f-cards">
        {findings.map((finding) => (
          <FindingCard key={finding.finding_id} finding={finding} />
        ))}
      </ul>
    </>
  );
}