/* Typed API client for the Validation page. Mirrors the backend response
   models in app/api/validation_models.py. All data is read-only; the
   backend is the source of truth for verdicts, confidence and reasoning.
   Nothing here triggers LLM validation. */

import { fetchJson } from "./dashboard";

export interface ValidationKpi {
  available: boolean;
  value: number;
}

export interface ValidationKpis {
  total_validations: ValidationKpi;
  true_positives: ValidationKpi;
  false_positives: ValidationKpi;
  uncertain: ValidationKpi;
  pending: ValidationKpi;
}

export interface ValidationRow {
  finding_id: string;
  vulnerability_type: string | null;
  severity: string | null;
  priority: string | null; // from the stored risk assessment, when present
  repository: string | null;
  file: string | null;
  confidence: number | null; // validation confidence (0-1), never recalculated
  verdict: string | null; // true_positive / false_positive / uncertain
  reasoning: string | null;
  evidence_used: string[];
  validated_at: string | null;
  proof_status: string | null;
}

export interface ValidationSummary {
  has_findings: boolean;
  kpis: ValidationKpis;
  records: ValidationRow[];
}

export function getValidationSummary(): Promise<ValidationSummary> {
  return fetchJson<ValidationSummary>("/api/validation");
}
