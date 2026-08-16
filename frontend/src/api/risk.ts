/* Typed API client for the Risk & SLA page. Mirrors the backend response
   models in app/api/risk_models.py. All data is read-only; the backend is
   the source of truth for scores, priorities, SLA state and escalations. */

import { fetchJson } from "./dashboard";
import { requestJson } from "./projects";

export interface RiskKpi {
  available: boolean;
  value: number;
}

export interface RiskKpis {
  total_assessments: RiskKpi;
  critical_p0: RiskKpi;
  high_p1: RiskKpi;
  active_slas: RiskKpi;
  sla_breaches: RiskKpi;
  escalations: RiskKpi;
}

export interface PriorityBucket {
  priority: string; // "P0" .. "P4"
  count: number;
  percent: number;
}

export interface RiskBucket {
  label: string; // e.g. "61-80"
  count: number;
  percent: number;
}

export interface RiskFactor {
  name: string;
  value: string;
  points: number;
  description: string;
}

export interface RiskFindingRow {
  finding_id: string;
  priority: string;
  risk_score: number;
  severity: string;
  vulnerability_type: string;
  repository: string | null;
  file: string;
  validation: string | null; // verdict, or null when not validated
  proof: string | null; // proof status, or null when not proven
  sla: string; // record status, or "none"
  factors: RiskFactor[];
}

export interface SlaOverview {
  available: boolean;
  active: number;
  breached: number;
  resolved: number;
  no_sla: number;
}

export interface SlaRow {
  finding_id: string;
  vulnerability_type: string | null;
  priority: string;
  started_at: string;
  due_at: string | null;
  status: string;
  escalation_level: number;
  breached_at: string | null;
  remaining_seconds: number | null;
}

export interface EscalationRow {
  finding_id: string;
  previous_level: number;
  new_level: number;
  reason: string;
  created_at: string;
  vulnerability_type: string | null;
  priority: string | null;
}

export interface RiskSummary {
  has_findings: boolean;
  kpis: RiskKpis;
  priority_distribution: PriorityBucket[];
  risk_distribution: RiskBucket[];
  highest_risk_findings: RiskFindingRow[];
  sla_overview: SlaOverview;
  active_slas: SlaRow[];
  breaches: SlaRow[];
  escalations: EscalationRow[];
}

export function getRiskSummary(): Promise<RiskSummary> {
  return fetchJson<RiskSummary>("/api/risk/summary");
}

/* Mutation clients. Mirror the backend contracts in
   app/api/routes/risk.py and app/risk/models.py. The backend calculates
   every value; the frontend only submits the finding id. */

export interface RiskAssessmentOutput {
  finding_id: string;
  vulnerability_type: string;
  severity: string;
  risk_score: number;
  priority: string;
  factors: RiskFactor[];
  assessed_at: string;
  related_finding_ids: string[];
}

export interface SlaRecordOutput {
  finding_id: string;
  priority: string;
  started_at: string;
  due_at: string | null;
  status: string;
  breached_at: string | null;
  escalation_level: number;
  last_checked_at: string | null;
  resolved_at: string | null;
}

export interface EscalationEventOutput {
  finding_id: string;
  previous_level: number;
  new_level: number;
  reason: string;
  created_at: string;
}

export interface SlaCheckResultOutput {
  sla: SlaRecordOutput;
  escalation: EscalationEventOutput | null;
}

function stagePost(url: string, scanRunId?: string): Promise<unknown> {
  /* Per-finding stage actions accept an optional scan_run_id context (Phase
     14J): the backend records the action as an explicit execution of that
     stage against the run. Clients that omit it send no body at all - the
     wire contract is unchanged for existing callers. */
  const options: RequestInit = { method: "POST" };
  if (scanRunId) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify({ scan_run_id: scanRunId });
  }
  return requestJson(url, options);
}

export function assessRisk(
  findingId: string,
  scanRunId?: string,
): Promise<RiskAssessmentOutput> {
  return stagePost(
    `/api/findings/${encodeURIComponent(findingId)}/risk`,
    scanRunId,
  ) as Promise<RiskAssessmentOutput>;
}

export function createSla(
  findingId: string,
  scanRunId?: string,
): Promise<SlaRecordOutput> {
  return stagePost(
    `/api/findings/${encodeURIComponent(findingId)}/sla`,
    scanRunId,
  ) as Promise<SlaRecordOutput>;
}

export function checkSla(
  findingId: string,
  scanRunId?: string,
): Promise<SlaCheckResultOutput> {
  return stagePost(
    `/api/findings/${encodeURIComponent(findingId)}/sla/check`,
    scanRunId,
  ) as Promise<SlaCheckResultOutput>;
}
