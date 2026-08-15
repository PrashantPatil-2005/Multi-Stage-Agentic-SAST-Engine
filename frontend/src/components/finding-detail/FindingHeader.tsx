import { Link } from "react-router-dom";

import type { FindingDetail } from "../../api/findingDetail";
import { Badge } from "../ui/Badge";
import {
  priorityTone,
  severityTone,
  statusTone,
  vulnLabel,
} from "../findings/findingsHelpers";
import { deriveDetailStatus } from "./detailHelpers";

function MetaItem({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <div className="fd-meta__item">
      <span className="fd-meta__label">{label}</span>
      <span className={`fd-meta__value${mono ? " fd-meta__value--mono" : ""}`}>
        {value || "—"}
      </span>
    </div>
  );
}

export function FindingHeader({ detail }: { detail: FindingDetail }) {
  const status = deriveDetailStatus(detail);

  return (
    <header className="fd-header">
      <Link
        className="ui-button ui-button--secondary ui-button--md"
        to="/findings"
      >
        Back to Findings
      </Link>

      <div className="fd-header__title-row">
        <h1 className="fd-header__title">{vulnLabel(detail.vulnerability_type)}</h1>
        <div className="fd-header__badges">
          <Badge tone={priorityTone(detail.risk?.priority ?? null)}>
            {detail.risk?.priority ?? "—"}
          </Badge>
          <Badge tone={severityTone(detail.severity)}>
            {detail.severity.toUpperCase()}
          </Badge>
          <Badge tone={statusTone(status)}>{status}</Badge>
        </div>
      </div>

      <p className="fd-header__id">
        Finding ID: <span className="fd-header__id-value">{detail.finding_id}</span>
      </p>

      <dl className="fd-meta">
        <MetaItem label="Repository" value={detail.repository} />
        <MetaItem label="File" value={detail.source.file} mono />
        <MetaItem label="Source" value={detail.source.snippet} mono />
        <MetaItem label="Sink" value={detail.sink.snippet} mono />
      </dl>
    </header>
  );
}
