import type { ScanRun, ScanRunStatus } from "../../api/scans";
import { Badge } from "../ui/Badge";
import { formatTimestamp } from "./detailHelpers";

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function runTone(status: ScanRunStatus) {
  switch (status) {
    case "completed":
      return "success" as const;
    case "failed":
      return "danger" as const;
    case "running":
      return "warning" as const;
    default:
      return "neutral" as const;
  }
}

function runLabel(run: ScanRun): string {
  return `#${shortId(run.scan_run_id)} · ${run.status} · ${formatTimestamp(
    run.started_at,
  )}`;
}

/** Run-context selector for per-finding stage actions (Phase 14J).
 *
 * A finding may be produced by several scan runs (deterministic ids repeat
 * across rescans). The backend records a stage action against exactly one
 * explicit scan run, so:
 * - no producing runs -> no selector (actions run without a run context);
 * - one producing run -> shown as a static context, used automatically;
 * - several producing runs -> the user must pick one explicitly before any
 *   action is enabled; the selected value is the real backend scan_run_id.
 */
export function RunContextSelect({
  runs,
  value,
  onChange,
}: {
  runs: ScanRun[];
  value: string | null;
  onChange: (scanRunId: string | null) => void;
}) {
  if (runs.length === 0) {
    return null;
  }

  if (runs.length === 1) {
    const run = runs[0];
    return (
      <div className="fd-runcontext">
        <span className="fd-panel__label">Run context</span>
        <span className="fd-runcontext__static" role="status">
          <Badge tone={runTone(run.status)}>{run.status}</Badge>{" "}
          <span className="fd-panel__value">{runLabel(run)}</span>
        </span>
      </div>
    );
  }

  return (
    <div className="fd-runcontext">
      <label className="fd-panel__label" htmlFor="fd-run-context">
        Run context
      </label>
      <select
        id="fd-run-context"
        className="fd-runcontext__select"
        aria-label="Scan run context"
        value={value ?? ""}
        onChange={(event) =>
          onChange(event.target.value === "" ? null : event.target.value)
        }
      >
        <option value="">Select a scan run…</option>
        {runs.map((run) => (
          <option key={run.scan_run_id} value={run.scan_run_id}>
            {runLabel(run)}
          </option>
        ))}
      </select>
    </div>
  );
}
