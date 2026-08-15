import type { ValidationRow } from "../../api/validation";

export interface ValidationReasoningProps {
  row: ValidationRow;
}

export function ValidationReasoning({ row }: ValidationReasoningProps) {
  const hasReasoning = row.reasoning !== null && row.reasoning !== "";
  return (
    <details
      className="val-reason"
      onClick={(event) => event.stopPropagation()}
    >
      <summary className="val-reason__summary">Reasoning</summary>
      <div className="val-reason__panel">
        {!hasReasoning ? (
          <p className="val-reason__empty">No validation reasoning available</p>
        ) : (
          <p className="val-reason__text">{row.reasoning}</p>
        )}
        {row.evidence_used.length > 0 ? (
          <>
            <h4 className="val-reason__subtitle">Evidence used</h4>
            <ul className="val-reason__list">
              {row.evidence_used.map((item) => (
                <li className="val-reason__item" key={item}>
                  {item}
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
    </details>
  );
}
