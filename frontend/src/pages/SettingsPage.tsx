import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { vulnLabel } from "../components/findings/findingsHelpers";
import "./settings.css";

const SUPPORTED_RULES = ["sql_injection", "command_injection", "ssrf"];

export function SettingsPage() {
  return (
    <div className="settings-page">
      <PageHeader
        title="Settings"
        description="Platform configuration (read-only)"
        actions={<Badge tone="info">Read-only</Badge>}
      />
      <Card title="Platform configuration">
        <dl className="settings-list">
          <div className="settings-list__row">
            <dt>LLM provider</dt>
            <dd>Hugging Face (OpenAI-compatible)</dd>
          </div>
          <div className="settings-list__row">
            <dt>LLM model</dt>
            <dd>
              Configured on the backend via <code>LLM_MODEL</code>
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>LLM timeout</dt>
            <dd>
              30 seconds (<code>LLM_TIMEOUT_SECONDS</code>)
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>Database</dt>
            <dd>
              SQLite (local development; PostgreSQL via{" "}
              <code>SAST_DATABASE_URL</code>)
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>Scanner</dt>
            <dd>
              Built-in taint engine (our-sast); Semgrep comparison in
              benchmarks
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>Vulnerability rules</dt>
            <dd className="settings-list__badges">
              {SUPPORTED_RULES.map((rule) => (
                <Badge key={rule} tone="neutral">
                  {vulnLabel(rule)}
                </Badge>
              ))}
            </dd>
          </div>
          <div className="settings-list__row">
            <dt>Proof sandbox</dt>
            <dd>Sandboxed execution; network access disabled, 10 second timeout</dd>
          </div>
        </dl>
        <p className="settings-list__note">
          Configuration is read-only and managed on the backend through
          environment variables (.env). Secrets are never displayed.
        </p>
      </Card>
    </div>
  );
}