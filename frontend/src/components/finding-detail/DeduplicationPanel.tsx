import { Link } from "react-router-dom";

import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";

export function DeduplicationPanel({ detail }: { detail: FindingDetail }) {
  const dedup = detail.dedup;

  return (
    <Card title="Deduplication">
      {!dedup ? (
        <p className="fd-panel__empty">No duplicate group</p>
      ) : (
        <div className="fd-panel__body">
          <div className="fd-panel__line">
            <span className="fd-panel__label">Canonical Finding</span>
            {dedup.is_canonical ? (
              <Badge tone="success">Canonical finding</Badge>
            ) : (
              <Link
                className="fd-panel__link"
                to={`/findings/${dedup.canonical_finding_id}`}
              >
                {dedup.canonical_finding_id}
              </Link>
            )}
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Occurrences</span>
            <span className="fd-panel__value">
              {dedup.occurrence_count}
            </span>
          </div>
          <div className="fd-panel__line">
            <span className="fd-panel__label">Group Fingerprint</span>
            <span className="fd-panel__value fd-panel__mono" title={dedup.fingerprint}>
              {dedup.fingerprint.slice(0, 16)}…
            </span>
          </div>
          {dedup.related_finding_ids.length > 0 ? (
            <div className="fd-panel__line fd-panel__line--top">
              <span className="fd-panel__label">Related Findings</span>
              <ul className="fd-panel__related">
                {dedup.related_finding_ids.map((id) => (
                  <li key={id}>
                    <Link className="fd-panel__link" to={`/findings/${id}`}>
                      {id}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      )}
    </Card>
  );
}
