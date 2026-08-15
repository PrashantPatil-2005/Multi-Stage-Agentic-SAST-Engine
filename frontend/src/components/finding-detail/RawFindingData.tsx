import { useId } from "react";

import type { FindingDetail } from "../../api/findingDetail";
import { Card } from "../ui/Card";

export function RawFindingData({ detail }: { detail: FindingDetail }) {
  const summaryId = useId();
  const contentId = useId();
  const json = JSON.stringify(detail, null, 2);

  return (
    <Card title="Raw Finding Data">
      <details className="fd-raw">
        <summary id={summaryId} aria-describedby={contentId}>
          Expand raw finding metadata
        </summary>
        <pre className="fd-raw__pre" id={contentId} aria-label="Raw finding JSON">
          <code>{json}</code>
        </pre>
      </details>
      <p className="fd-raw__note">
        Read-only finding metadata returned by the backend. Secrets and
        internal configuration are never exposed.
      </p>
    </Card>
  );
}
