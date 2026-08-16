/* Typed API client for scan run lineage endpoints (Phase 14D/14G).
   Mirrors the backend response models in app/scan/run_models.py and
   app/scan/models.py
   (GET /api/projects/{id}/scans, GET /api/scans, GET /api/scans/{id},
    GET /api/scans/{id}/findings). */

import { requestJson } from "./projects";

export type ScanRunStatus = "pending" | "running" | "completed" | "failed";
export type StageStatus = "pending" | "running" | "completed" | "failed";

export interface ScanRun {
  scan_run_id: string;
  project_id: string;
  status: ScanRunStatus;
  started_at: string;
  completed_at: string | null;
  scanned_file_count: number | null;
  total_findings: number | null;
  error: string | null;
  created_at: string;
}

export interface ScanStageRun {
  scan_run_id: string;
  stage_name: string;
  status: StageStatus;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  /** How many times this stage has been executed within the run. */
  execution_count?: number;
  last_execution_at?: string | null;
}

/** One explicit execution of a stage within a scan run (append-only). */
export interface ScanStageExecution {
  execution_id: string;
  scan_run_id: string;
  stage_name: string;
  status: StageStatus;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

export interface ScanRunDetail {
  run: ScanRun;
  stages: ScanStageRun[];
  executions?: ScanStageExecution[];
}

export function getProjectScans(projectId: string): Promise<ScanRun[]> {
  return requestJson<ScanRun[]>(
    `/api/projects/${encodeURIComponent(projectId)}/scans`,
    { method: "GET" },
  );
}

export function getScanRun(scanRunId: string): Promise<ScanRunDetail> {
  return requestJson<ScanRunDetail>(
    `/api/scans/${encodeURIComponent(scanRunId)}`,
    { method: "GET" },
  );
}

/** Recent scan runs across all projects, newest first (read-only). */
export function getAllScans(limit = 10): Promise<ScanRun[]> {
  return requestJson<ScanRun[]>(`/api/scans?limit=${limit}`, { method: "GET" });
}

export interface ScanFindingSource {
  file: string;
  line: number;
  snippet: string;
  kind: string;
}

export interface ScanFindingSink {
  file: string;
  line: number;
  snippet: string;
  kind: string;
}

export interface ScanFindingTaintStep {
  file: string;
  line: number;
  snippet: string;
  step_type:
    | "source"
    | "assignment"
    | "propagation"
    | "string_construction"
    | "sink";
}

export interface ScanFindingEvidence {
  source_snippet: string;
  sink_snippet: string;
  taint_path: ScanFindingTaintStep[];
  relevant_lines: number[];
  sanitizer_observations: string[];
}

/** Mirror of app/scan/models.py CandidateFinding (scan-run findings). */
export interface ScanFinding {
  id: string;
  vulnerability_type: string;
  severity: string;
  confidence: number;
  status: "candidate";
  source: ScanFindingSource;
  sink: ScanFindingSink;
  taint_path: ScanFindingTaintStep[];
  evidence: ScanFindingEvidence;
}

/** Findings produced by one scan run (explicit lineage, read-only). */
export function getScanFindings(scanRunId: string): Promise<ScanFinding[]> {
  return requestJson<ScanFinding[]>(
    `/api/scans/${encodeURIComponent(scanRunId)}/findings`,
    { method: "GET" },
  );
}