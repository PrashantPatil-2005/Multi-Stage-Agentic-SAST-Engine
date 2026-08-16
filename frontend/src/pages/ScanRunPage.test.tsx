import { readFileSync } from "node:fs";

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  ScanFinding,
  ScanRun,
  ScanRunDetail,
  StageStatus,
} from "../api/scans";
import { ScanRunPage } from "./ScanRunPage";

const PROJECT_ID = "aaaa0000aaaa0000aaaa0000aaaa0000";

const PROJECT_DETAIL = {
  id: PROJECT_ID,
  name: "web-app",
  source_type: "git",
  location: "https://github.com/example/web-app",
  language: "python",
  status: "prepared",
  created_at: "2026-08-15T09:00:00Z",
  summary: {
    fetched_files: 5,
    fetched_bytes: 2048,
    python_files: 4,
    parse_failures: 0,
    total_lines: 120,
    function_count: 10,
    class_count: 2,
    call_count: 30,
    import_count: 8,
    assignment_count: 40,
  },
  files: [],
};

function run(overrides: Partial<ScanRun>): ScanRun {
  return {
    scan_run_id: "scan-run-0001",
    project_id: PROJECT_ID,
    status: "completed",
    started_at: "2026-08-16T07:10:00Z",
    completed_at: "2026-08-16T07:10:05Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T07:10:00Z",
    ...overrides,
  };
}

function finding(overrides: Partial<ScanFinding>): ScanFinding {
  return {
    id: "fid-sqli-0001",
    vulnerability_type: "sql_injection",
    severity: "high",
    confidence: 0.9,
    status: "candidate",
    source: {
      file: "app.py",
      line: 10,
      snippet: "request.args.get('id')",
      kind: "request_param",
    },
    sink: {
      file: "app.py",
      line: 15,
      snippet: "cursor.execute(query)",
      kind: "sql_execute",
    },
    taint_path: [],
    evidence: {
      source_snippet: "request.args.get('id')",
      sink_snippet: "cursor.execute(query)",
      taint_path: [],
      relevant_lines: [10, 15],
      sanitizer_observations: [],
    },
    ...overrides,
  };
}

function mockScanRun(options: {
  runId?: string;
  detail?: ScanRunDetail;
  findings?: ScanFinding[];
  detailStatus?: number;
  findingsStatus?: number;
  projectStatus?: number;
  onCall?: (url: string) => void;
}) {
  const runId = options.runId ?? "scan-run-0001";
  const completedRun = run({});
  const detail = options.detail ?? {
    run: completedRun,
    stages: [
      {
        scan_run_id: runId,
        stage_name: "SCAN",
        status: "completed",
        started_at: "2026-08-16T07:10:00Z",
        completed_at: "2026-08-16T07:10:05Z",
        error: null,
      },
      {
        scan_run_id: runId,
        stage_name: "DEDUPLICATE",
        status: "pending",
        started_at: null,
        completed_at: null,
        error: null,
      },
      {
        scan_run_id: runId,
        stage_name: "RISK",
        status: "pending",
        started_at: null,
        completed_at: null,
        error: null,
      },
      {
        scan_run_id: runId,
        stage_name: "SLA",
        status: "pending",
        started_at: null,
        completed_at: null,
        error: null,
      },
    ],
  };
  const findings = options.findings ?? [finding({}), finding({ id: "fid-cmdi-0001", vulnerability_type: "command_injection" })];
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url);
      expect(method).toBe("GET");
      if (url === `/api/scans/${runId}`) {
        if (options.detailStatus === 404) {
          return { ok: false, status: 404, json: async () => ({ detail: `scan run not found: ${runId}` }) };
        }
        return { ok: true, status: 200, json: async () => detail };
      }
      if (url === `/api/scans/${runId}/findings`) {
        if (options.findingsStatus === 404) {
          return { ok: false, status: 404, json: async () => ({ detail: `scan run not found: ${runId}` }) };
        }
        return { ok: true, status: 200, json: async () => findings };
      }
      if (url === `/api/projects/${PROJECT_ID}`) {
        if (options.projectStatus === 404) {
          return { ok: false, status: 404, json: async () => ({ detail: "project not found" }) };
        }
        return { ok: true, status: 200, json: async () => PROJECT_DETAIL };
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage(initialEntry = "/scans/scan-run-0001") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/scans/:scanRunId" element={<ScanRunPage />} />
        <Route path="/repositories" element={<div>repositories-placeholder</div>} />
        <Route path="/findings/:id" element={<div>finding-detail-placeholder</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function loaded() {
  await screen.findByRole("heading", { name: "Scan Run", level: 1 });
  await screen.findByText("Run ID:");
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("scan run page", () => {
  it("displays the real backend run values", async () => {
    mockScanRun({});
    renderPage();
    await loaded();
    const runCard = screen.getByText("Run ID:").closest("section") as HTMLElement;
    expect(within(runCard).getByText("scan-run-0001")).toBeInTheDocument();
    expect(within(runCard).getByText("completed")).toBeInTheDocument();
    expect(within(runCard).getByText("127")).toBeInTheDocument();
    expect(within(runCard).getByText("3")).toBeInTheDocument();
    expect(
      within(runCard).getAllByText(/Aug 16, 2026/).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it("links the repository with its real project id", async () => {
    mockScanRun({});
    renderPage();
    await loaded();
    const repoLink = await screen.findByRole("link", { name: "web-app" });
    expect(repoLink).toHaveAttribute("href", `/repositories?project_id=${PROJECT_ID}`);
    expect(
      screen.getByRole("link", { name: "Open Repository" }),
    ).toHaveAttribute("href", `/repositories?project_id=${PROJECT_ID}`);
  });

  it("renders stage statuses honestly: SCAN completed, later stages pending", async () => {
    mockScanRun({});
    renderPage();
    await loaded();
    const stages = screen.getByRole("table");
    const scanRow = within(stages)
      .getAllByRole("row")
      .find((row) => within(row).queryByText("SCAN"));
    expect(scanRow).toBeDefined();
    expect(within(scanRow as HTMLElement).getByText("completed")).toBeInTheDocument();
    for (const stageName of ["DEDUPLICATE", "RISK", "SLA"]) {
      const row = within(stages)
        .getAllByRole("row")
        .find((candidate) => within(candidate).queryByText(stageName));
      expect(row).toBeDefined();
      expect(within(row as HTMLElement).getByText("pending")).toBeInTheDocument();
    }
  });

  it("shows real stage execution counts: SCAN 1, unexecuted stages 0", async () => {
    mockScanRun({
      detail: {
        run: run({}),
        stages: [
          {
            scan_run_id: "scan-run-0001",
            stage_name: "SCAN",
            status: "completed",
            started_at: "2026-08-16T07:10:00Z",
            completed_at: "2026-08-16T07:10:05Z",
            error: null,
            execution_count: 1,
            last_execution_at: "2026-08-16T07:10:00Z",
          },
          {
            scan_run_id: "scan-run-0001",
            stage_name: "DEDUPLICATE",
            status: "completed",
            started_at: "2026-08-16T07:11:00Z",
            completed_at: "2026-08-16T07:11:02Z",
            error: null,
            execution_count: 2,
            last_execution_at: "2026-08-16T07:11:00Z",
          },
          {
            scan_run_id: "scan-run-0001",
            stage_name: "RISK",
            status: "pending",
            started_at: null,
            completed_at: null,
            error: null,
            execution_count: 0,
          },
          {
            scan_run_id: "scan-run-0001",
            stage_name: "SLA",
            status: "pending",
            started_at: null,
            completed_at: null,
            error: null,
            execution_count: 0,
          },
        ],
        executions: [
          {
            execution_id: "exec-1",
            scan_run_id: "scan-run-0001",
            stage_name: "SCAN",
            status: "completed",
            started_at: "2026-08-16T07:10:00Z",
            completed_at: "2026-08-16T07:10:05Z",
            error: null,
          },
          {
            execution_id: "exec-2",
            scan_run_id: "scan-run-0001",
            stage_name: "DEDUPLICATE",
            status: "completed",
            started_at: "2026-08-16T07:11:00Z",
            completed_at: "2026-08-16T07:11:02Z",
            error: null,
          },
        ],
      },
    });
    renderPage();
    await loaded();
    const stages = screen.getByRole("table");
    const rowFor = (stageName: string) =>
      within(stages)
        .getAllByRole("row")
        .find((row) => within(row).queryByText(stageName));
    const scanRow = rowFor("SCAN");
    expect(
      within(scanRow as HTMLElement).getAllByText("1").length,
    ).toBeGreaterThanOrEqual(1);
    const dedupRow = rowFor("DEDUPLICATE");
    expect(
      within(dedupRow as HTMLElement).getAllByText("2").length,
    ).toBeGreaterThanOrEqual(1);
    for (const stageName of ["RISK", "SLA"]) {
      const row = rowFor(stageName);
      expect(
        within(row as HTMLElement).getAllByText("0").length,
      ).toBeGreaterThanOrEqual(1);
    }
    expect(
      screen.getByText(/Executions counts every recorded run of a stage/),
    ).toBeInTheDocument();
  });

  it("shows the full eight-stage pipeline with real backend statuses", async () => {
    const stageList: Array<[string, StageStatus]> = [
      ["PREPARE", "completed"],
      ["SCAN", "completed"],
      ["DEDUPLICATE", "completed"],
      ["RISK", "completed"],
      ["SLA", "pending"],
      ["VALIDATE", "completed"],
      ["PROVE", "failed"],
      ["APPROVAL", "pending"],
    ];
    const stages = stageList.map(([stage_name, status]) => ({
      scan_run_id: "scan-run-0001",
      stage_name,
      status,
      started_at: "2026-08-16T07:10:00Z",
      completed_at: status === "pending" ? null : "2026-08-16T07:10:05Z",
      error: status === "failed" ? "proof harness timed out" : null,
      execution_count: status === "pending" ? 0 : 1,
    }));
    mockScanRun({
      detail: { run: run({}), stages },
    });
    renderPage();
    await loaded();
    const table = screen.getByRole("table");
    for (const [stageName, status] of [
      ["PREPARE", "completed"],
      ["SCAN", "completed"],
      ["DEDUPLICATE", "completed"],
      ["RISK", "completed"],
      ["SLA", "pending"],
      ["VALIDATE", "completed"],
      ["PROVE", "failed"],
      ["APPROVAL", "pending"],
    ]) {
      const row = within(table)
        .getAllByRole("row")
        .find((candidate) => within(candidate).queryByText(stageName));
      expect(row).toBeDefined();
      expect(within(row as HTMLElement).getByText(status)).toBeInTheDocument();
    }
    expect(screen.getByText("proof harness timed out")).toBeInTheDocument();
  });

  it("renders the append-only execution history with real backend ids", async () => {
    mockScanRun({
      detail: {
        run: run({}),
        stages: [],
        executions: [
          {
            execution_id: "exec-aaaa1111bbbb2222cccc3333dddd4444",
            scan_run_id: "scan-run-0001",
            stage_name: "VALIDATE",
            status: "failed",
            started_at: "2026-08-16T09:31:12Z",
            completed_at: "2026-08-16T09:31:13Z",
            error: "provider not configured",
          },
          {
            execution_id: "exec-eeee5555ffff6666",
            scan_run_id: "scan-run-0001",
            stage_name: "VALIDATE",
            status: "completed",
            started_at: "2026-08-16T09:33:19Z",
            completed_at: "2026-08-16T09:33:22Z",
            error: null,
          },
          {
            execution_id: "exec-cccc7777",
            scan_run_id: "scan-run-0001",
            stage_name: "APPROVAL",
            status: "completed",
            started_at: "2026-08-16T09:40:00Z",
            completed_at: "2026-08-16T09:40:01Z",
            error: null,
          },
        ],
      },
    });
    renderPage();
    await loaded();
    const history = screen
      .getByText("Stage Execution History")
      .closest("section") as HTMLElement;
    const items = within(history).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(within(items[0]).getByText("VALIDATE")).toBeInTheDocument();
    expect(within(items[0]).getByText("failed")).toBeInTheDocument();
    expect(within(items[0]).getByText("provider not configured")).toBeInTheDocument();
    expect(within(items[1]).getByText("completed")).toBeInTheDocument();
    expect(within(items[2]).getByText("APPROVAL")).toBeInTheDocument();
    expect(
      within(history).getAllByText(/Aug 16, 2026/).length,
    ).toBeGreaterThanOrEqual(3);
    expect(within(history).getByText("#exec-aaa")).toBeInTheDocument();
  });

  it("shows an honest empty state for execution history", async () => {
    mockScanRun({});
    renderPage();
    await loaded();
    expect(
      screen.getByText("No stage executions recorded yet."),
    ).toBeInTheDocument();
  });

  it("renders findings produced by the scan with real finding ids", async () => {
    mockScanRun({
      findings: [
        finding({}),
        finding({ id: "fid-cmdi-0001", vulnerability_type: "command_injection" }),
      ],
    });
    renderPage();
    await loaded();
    const section = screen
      .getByText("Findings produced by this scan")
      .closest("section") as HTMLElement;
    const links = within(section).getAllByRole("link", { name: "Open finding" });
    expect(links).toHaveLength(2);
    expect(links[0]).toHaveAttribute("href", "/findings/fid-sqli-0001");
    expect(links[1]).toHaveAttribute("href", "/findings/fid-cmdi-0001");
    expect(within(section).getByText("sql_injection")).toBeInTheDocument();
    expect(within(section).getByText("command_injection")).toBeInTheDocument();
  });

  it("shows an honest empty state when the scan produced no findings", async () => {
    mockScanRun({ findings: [] });
    renderPage();
    await loaded();
    expect(
      await screen.findByText("No findings were produced by this scan."),
    ).toBeInTheDocument();
  });

  it("renders a failed scan's error safely", async () => {
    mockScanRun({
      detail: {
        run: run({
          status: "failed",
          completed_at: "2026-08-16T07:10:02Z",
          scanned_file_count: null,
          total_findings: null,
          error: "SCAN stage failed: rule engine timeout",
        }),
        stages: [
          {
            scan_run_id: "scan-run-0001",
            stage_name: "SCAN",
            status: "failed",
            started_at: "2026-08-16T07:10:00Z",
            completed_at: "2026-08-16T07:10:02Z",
            error: "rule engine timeout",
          },
        ],
      },
      findings: [],
    });
    renderPage();
    await loaded();
    const runCard = screen.getByText("Run ID:").closest("section") as HTMLElement;
    expect(within(runCard).getAllByText("failed").length).toBeGreaterThan(0);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("SCAN stage failed: rule engine timeout");
    expect(alert.textContent).not.toContain("Traceback");
    expect(within(runCard).getAllByText("—").length).toBeGreaterThanOrEqual(2);
  });

  it("shows Run not found for an unknown scan run", async () => {
    mockScanRun({ runId: "does-not-exist", detailStatus: 404, findingsStatus: 404 });
    renderPage("/scans/does-not-exist");
    expect(
      await screen.findByRole("alert", { name: "Scan run not found" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Scan run not found.")).toBeInTheDocument();
  });

  it("shows a load error with Retry that recovers", async () => {
    let failing = true;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (failing) throw new Error("network down");
      const url = String(input);
      if (url === "/api/scans/scan-run-0001") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            run: run({}),
            stages: [
              {
                scan_run_id: "scan-run-0001",
                stage_name: "SCAN",
                status: "completed",
                started_at: "2026-08-16T07:10:00Z",
                completed_at: "2026-08-16T07:10:05Z",
                error: null,
              },
            ],
          }),
        };
      }
      if (url === "/api/scans/scan-run-0001/findings") {
        return { ok: true, status: 200, json: async () => [] };
      }
      if (url === `/api/projects/${PROJECT_ID}`) {
        return { ok: true, status: 200, json: async () => PROJECT_DETAIL };
      }
      throw new Error(`unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByRole("alert", { name: "Scan run load error" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Unable to load scan run.")).toBeInTheDocument();

    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await loaded();
    expect(screen.getByText("scan-run-0001")).toBeInTheDocument();
  });

  it("shows a structured loading state before data arrives", async () => {
    const fetchMock = vi.fn(
      () =>
        new Promise<never>(() => {
          /* never resolves during the test */
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByLabelText("Loading scan run"),
    ).toBeInTheDocument();
    expect(screen.queryByText("Run ID:")).not.toBeInTheDocument();
  });

  it("only issues read-only GET requests and no shell/fs source", async () => {
    const onCall = vi.fn<(url: string) => void>();
    mockScanRun({ onCall });
    renderPage();
    await loaded();
    const urls = onCall.mock.calls.map(([url]) => url);
    expect(urls).toEqual(
      expect.arrayContaining([
        "/api/scans/scan-run-0001",
        "/api/scans/scan-run-0001/findings",
        `/api/projects/${PROJECT_ID}`,
      ]),
    );
    for (const url of urls) {
      expect(url).not.toContain("findings?");
      expect(url).not.toContain("?");
    }
    const pageSource = readFileSync("src/pages/ScanRunPage.tsx", "utf-8");
    const hookSource = readFileSync("src/hooks/useScanRun.ts", "utf-8");
    const source = pageSource + "\n" + hookSource;
    for (const forbidden of [
      "child_process",
      "spawn",
      "execSync",
      "node:fs",
      "Math.random",
      "setInterval",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });
});
