import { useCallback, useEffect, useState } from "react";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import {
  DefectDojoConnectionTest,
  DefectDojoStatus,
  DefectDojoTicket,
  testDefectDojoConnection,
  getDefectDojoStatus,
  getDefectDojoTickets,
  syncDefectDojoFindings,
} from "../api/defectdojo";
import "./defectdojo.css";

function statusBadge(status: DefectDojoStatus) {
  if (!status.configured) return <Badge tone="neutral">Not Configured</Badge>;
  if (!status.enabled) return <Badge tone="warning">Disabled</Badge>;
  return <Badge tone="success">Enabled</Badge>;
}

function ticketStatusBadge(status: string) {
  switch (status) {
    case "created":
      return <Badge tone="success">Created</Badge>;
    case "synced":
      return <Badge tone="info">Synced</Badge>;
    case "pending":
      return <Badge tone="warning">Pending</Badge>;
    case "error":
      return <Badge tone="danger">Error</Badge>;
    default:
      return <Badge tone="neutral">{status}</Badge>;
  }
}

export function DefectDojoPage() {
  const [status, setStatus] = useState<DefectDojoStatus | null>(null);
  const [tickets, setTickets] = useState<DefectDojoTicket[]>([]);
  const [connectionTest, setConnectionTest] =
    useState<DefectDojoConnectionTest | null>(null);
  const [syncResult, setSyncResult] = useState<{
    total: number;
    created: number;
    errors: number;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, t] = await Promise.all([
        getDefectDojoStatus(),
        getDefectDojoTickets(),
      ]);
      setStatus(s);
      setTickets(t);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load status");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleTestConnection = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await testDefectDojoConnection();
      setConnectionTest(result);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Connection test failed");
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await syncDefectDojoFindings();
      setSyncResult({
        total: result.total,
        created: result.created,
        errors: result.errors,
      });
      await load(); // refresh tickets
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Sync failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="defectdojo-page">
      <PageHeader
        title="DefectDojo Integration"
        description="Create and manage remediation tickets in DefectDojo"
        actions={
          <div className="defectdojo-actions">
            <button
              className="btn btn-secondary"
              onClick={handleTestConnection}
              disabled={loading}
            >
              Test Connection
            </button>
            <button
              className="btn btn-primary"
              onClick={handleSync}
              disabled={loading}
            >
              Sync Findings
            </button>
          </div>
        }
      />

      {error && <div className="defectdojo-error">{error}</div>}

      <Card title="Connection Status">
        {status ? (
          <dl className="defectdojo-status-list">
            <div className="defectdojo-status-row">
              <dt>Status</dt>
              <dd>{statusBadge(status)}</dd>
            </div>
            <div className="defectdojo-status-row">
              <dt>URL</dt>
              <dd>{status.url || "Not configured"}</dd>
            </div>
            <div className="defectdojo-status-row">
              <dt>Product ID</dt>
              <dd>{status.product_id ?? "Not set"}</dd>
            </div>
            <div className="defectdojo-status-row">
              <dt>Engagement ID</dt>
              <dd>{status.engagement_id ?? "Not set"}</dd>
            </div>
            <div className="defectdojo-status-row">
              <dt>Tickets</dt>
              <dd>{status.ticket_count}</dd>
            </div>
            {status.tickets_with_error > 0 && (
              <div className="defectdojo-status-row">
                <dt>Errors</dt>
                <dd>
                  <Badge tone="danger">{status.tickets_with_error}</Badge>
                </dd>
              </div>
            )}
          </dl>
        ) : (
          <p>Loading status...</p>
        )}
      </Card>

      {connectionTest && (
        <Card title="Connection Test Result">
          <div
            className={`defectdojo-test-result ${connectionTest.success ? "success" : "failure"}`}
          >
            <p>{connectionTest.message}</p>
            {connectionTest.version && (
              <p>Version: {connectionTest.version}</p>
            )}
          </div>
        </Card>
      )}

      {syncResult && (
        <Card title="Sync Result">
          <div className="defectdojo-sync-result">
            <p>
              Total: {syncResult.total} | Created: {syncResult.created} |{" "}
              Errors: {syncResult.errors}
            </p>
          </div>
        </Card>
      )}

      <Card title={`Tickets (${tickets.length})`}>
        {tickets.length === 0 ? (
          <p className="defectdojo-empty">
            No tickets yet. Click "Sync Findings" to create DefectDojo tickets
            for your SAST findings.
          </p>
        ) : (
          <table className="defectdojo-tickets-table">
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Status</th>
                <th>DefectDojo ID</th>
                <th>Error</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {tickets.map((ticket) => (
                <tr key={ticket.finding_id}>
                  <td className="finding-id">{ticket.finding_id.slice(0, 12)}...</td>
                  <td>{ticketStatusBadge(ticket.status)}</td>
                  <td>
                    {ticket.defectdojo_finding_id ? (
                      <a
                        href={ticket.defectdojo_url || "#"}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        #{ticket.defectdojo_finding_id}
                      </a>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="error-text">{ticket.error_message || "—"}</td>
                  <td>
                    {ticket.created_at
                      ? new Date(ticket.created_at).toLocaleString()
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
