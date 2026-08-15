/* Typed API client for the Risk & SLA page. Mirrors the backend response
   models in app/api/risk_models.py. All data is read-only; the backend is
   the source of truth for scores, priorities, SLA state and escalations. */

import { fetchJson } from "./dashboard";

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
