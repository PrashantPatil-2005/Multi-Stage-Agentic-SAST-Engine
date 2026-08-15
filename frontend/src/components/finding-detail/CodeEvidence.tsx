import type { FindingDetail, FindingDetailTaintStep } from "../../api/findingDetail";
import { Card } from "../ui/Card";
import { stepTypeLabel } from "./detailHelpers";

function CodeBlock({ snippet, label }: { snippet: string; label: string }) {
  return (
    <pre className="fd-code">
      <code aria-label={label}>{snippet || "—"}</code>
    </pre>
  );
}

function TaintStepRow({ step }: { step: FindingDetailTaintStep }) {
  return (
    <li className="fd-taint__step">
      <span className="fd-taint__line" aria-hidden="true">
        {step.line}
      </span>
      <span className="fd-taint__type">{stepTypeLabel(step.step_type)}</span>
      <pre className="fd-taint__snippet">
        <code>{step.snippet || "—"}</code>
      </pre>
    </li>
  );
}

export function CodeEvidence({ detail }: { detail: FindingDetail }) {
  const { source, sink } = detail;
  const hasTaintPath = detail.taint_path.length > 0;

  return (
    <Card title="Code Evidence">
      <div className="fd-evidence">
        <section className="fd-evidence__panel" aria-label="Source">
          <h3 className="fd-evidence__panel-title">Source</h3>
          <dl className="fd-kv">
            <div className="fd-kv__row">
              <dt>Source Type</dt>
              <dd>{source.kind || "—"}</dd>
            </div>
            <div className="fd-kv__row">
              <dt>Source File</dt>
              <dd className="fd-kv__mono">
                {source.file}:{source.line}
              </dd>
            </div>
            <div className="fd-kv__row">
              <dt>Source Line</dt>
              <dd className="fd-kv__mono">{source.line}</dd>
            </div>
          </dl>
          <CodeBlock snippet={source.snippet} label="Source snippet" />
        </section>

        <div className="fd-evidence__flow" aria-hidden="true">
          ↓
        </div>

        <section className="fd-evidence__panel" aria-label="Taint path">
          <h3 className="fd-evidence__panel-title">Taint Path</h3>
          {hasTaintPath ? (
            <ol className="fd-taint">
              {detail.taint_path.map((step, index) => (
                <TaintStepRow key={`${step.file}:${step.line}:${index}`} step={step} />
              ))}
            </ol>
          ) : (
            <p className="fd-evidence__empty">No taint path available</p>
          )}
        </section>

        <div className="fd-evidence__flow" aria-hidden="true">
          ↓
        </div>

        <section className="fd-evidence__panel" aria-label="Sink">
          <h3 className="fd-evidence__panel-title">Sink</h3>
          <dl className="fd-kv">
            <div className="fd-kv__row">
              <dt>Sink Type</dt>
              <dd>{sink.kind || "—"}</dd>
            </div>
            <div className="fd-kv__row">
              <dt>Sink File</dt>
              <dd className="fd-kv__mono">
                {sink.file}:{sink.line}
              </dd>
            </div>
            <div className="fd-kv__row">
              <dt>Sink Line</dt>
              <dd className="fd-kv__mono">{sink.line}</dd>
            </div>
          </dl>
          <CodeBlock snippet={sink.snippet} label="Sink snippet" />
        </section>
      </div>
    </Card>
  );
}
