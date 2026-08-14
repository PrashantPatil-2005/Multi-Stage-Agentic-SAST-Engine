import "./findings.css";

export interface FindingsEmptyStateProps {
  filtered: boolean;
}

export function FindingsEmptyState({ filtered }: FindingsEmptyStateProps) {
  return (
    <div className="f-empty">
      <p className="f-empty__title">No security findings</p>
      <p className="f-empty__text">
        {filtered
          ? "No findings match the current filters. Adjust or clear the filters to see more results."
          : "Findings appear here after a repository has been scanned. No security findings were detected yet."}
      </p>
    </div>
  );
}