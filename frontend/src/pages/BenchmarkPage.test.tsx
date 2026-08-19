import { readFileSync } from "node:fs";

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  BenchmarkComparison,
  BenchmarkFinding,
  BenchmarkList,
  BenchmarkMetrics,
  BenchmarkReport,
  BenchmarkResult,
  BenchmarkSummary,
} from "../api/benchmark";
import { BenchmarkPage } from "./BenchmarkPage";

const ID_A = "aaaa0000aaaa0000aaaa0000aaaa0000";
const ID_B = "bbbb0000bbbb0000bbbb0000bbbb0000";

const OUR_FINDINGS: BenchmarkFinding[] = [
  { tool: "our-sast", vulnerability_type: "sql_injection", file: "app.py", line: 12, function: "get_user", message: "sql_injection: sink", fingerprint: "ours-1" },
  { tool: "our-sast", vulnerability_type: "command_injection", file: "app.py", line: 33, function: "run_command", message: "command_injection: sink", fingerprint: "ours-2" },
  { tool: "our-sast", vulnerability_type: "ssrf", file: "app.py", line: 37, function: "fetch_url", message: "ssrf: sink", fingerprint: "ours-3" },
  { tool: "our-sast", vulnerability_type: "sql_injection", file: "db.py", line: 14, function: "execute", message: "sql_injection: sink", fingerprint: "ours-4" },
  { tool: "our-sast", vulnerability_type: "sql_injection", file: "db.py", line: 19, function: "query_users", message: "sql_injection: sink", fingerprint: "ours-5" },
];

const SEMGREP_FINDINGS: BenchmarkFinding[] = [
  { tool: "semgrep", vulnerability_type: "sql_injection", file: "app.py", line: 15, function: null, message: "sql finding", fingerprint: "sem-1" },
  { tool: "semgrep", vulnerability_type: "ssrf", file: "app.py", line: 40, function: null, message: "ssrf finding", fingerprint: "sem-2" },
  { tool: "semgrep", vulnerability_type: "path_traversal", file: "routes.py", line: 7, function: null, message: "extra finding", fingerprint: "sem-3" },
];

const OUR_METRICS: BenchmarkMetrics = {
  tool: "our-sast",
  true_positives: 5,
  false_positives: 0,
  false_negatives: 0,
  precision: 1,
  recall: 1,
  f1: 1,
  total_findings: 5,
};

const SEMGREP_METRICS: BenchmarkMetrics = {
  tool: "semgrep",
  true_positives: 2,
  false_positives: 1,
  false_negatives: 3,
  precision: 0.6667,
  recall: 0.4,
  f1: 0.5,
  total_findings: 3,
};

function ourResult(): BenchmarkResult {
  return {
    tool: "our-sast",
    available: true,
    findings: OUR_FINDINGS,
    duration_ms: 4120,
    error: null,
  };
}

function semgrepResult(overrides: Partial<BenchmarkResult> = {}): BenchmarkResult {
  return {
    tool: "semgrep",
    available: true,
    findings: SEMGREP_FINDINGS,
    duration_ms: 1900,
    error: null,
    ...overrides,
  };
}

function comparison(overrides: Partial<BenchmarkComparison> = {}): BenchmarkComparison {
  return {
    shared_findings: [OUR_FINDINGS[0], OUR_FINDINGS[2]],
    ours_only: [OUR_FINDINGS[1], OUR_FINDINGS[3], OUR_FINDINGS[4]],
    semgrep_only: [SEMGREP_FINDINGS[2]],
    shared_vulnerability_types: ["sql_injection", "ssrf"],
    safe_cases_detected_incorrectly: ["sql-app-get-user-safe"],
    ...overrides,
  };
}

function report(overrides: Partial<BenchmarkReport> = {}): BenchmarkReport {
  return {
    benchmark_id: ID_A,
    fixture: "vulnerable_python_app",
    ground_truth_count: 8,
    our_result: ourResult(),
    semgrep_result: semgrepResult(),
    metrics: [OUR_METRICS, SEMGREP_METRICS],
    comparison: comparison(),
    created_at: "2026-08-15T09:00:00Z",
    ...overrides,
  };
}

function reportWithSemgrepUnavailable(overrides: Partial<BenchmarkReport> = {}): BenchmarkReport {
  return report({
    benchmark_id: ID_B,
    created_at: "2026-08-14T09:00:00Z",
    semgrep_result: semgrepResult({
      available: false,
      findings: [],
      duration_ms: null,
      error:
        "semgrep CLI not installed; benchmark unavailable. No fake findings are reported in its place. (install semgrep separately to enable this benchmark)",
    }),
    metrics: [OUR_METRICS],
    comparison: comparison({
      shared_findings: [],
      ours_only: OUR_FINDINGS,
      semgrep_only: [],
      shared_vulnerability_types: ["command_injection", "sql_injection", "ssrf"],
      safe_cases_detected_incorrectly: [],
    }),
    ...overrides,
  });
}

function summaryOf(report: BenchmarkReport): BenchmarkSummary {
  const metrics = report.metrics;
  return {
    benchmark_id: report.benchmark_id,
    fixture: report.fixture,
    created_at: report.created_at,
    semgrep_available: report.semgrep_result.available,
    semgrep_error: report.semgrep_result.error,
    our_f1: metrics.find((m) => m.tool === "our-sast")?.f1 ?? null,
    semgrep_f1: metrics.find((m) => m.tool === "semgrep")?.f1 ?? null,
    ground_truth_cases: report.ground_truth_count,
    vulnerable_cases: 5,
    safe_cases: 3,
  };
}

function listOf(...reports: BenchmarkReport[]): BenchmarkList {
  return { has_reports: reports.length > 0, reports: reports.map(summaryOf) };
}

interface ApiOptions {
  list: BenchmarkList;
  reportById: Record<string, BenchmarkReport>;
  runResponse?: BenchmarkReport | Promise<BenchmarkReport>;
  onCall?: (url: string, method: string) => void;
}

function stubApi(options: ApiOptions) {
  const state: ApiOptions = { ...options };
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    state.onCall?.(url, method);
    if (method === "POST" && url === "/api/benchmarks/semgrep") {
      if (state.runResponse === undefined) {
        throw new Error("no run response configured");
      }
      const response = await state.runResponse;
      state.reportById[response.benchmark_id] = response;
      state.list = {
        has_reports: true,
        reports: [summaryOf(response), ...state.list.reports],
      };
      return { ok: true, status: 200, json: async () => response };
    }
    if (url === "/api/benchmarks") {
      return { ok: true, status: 200, json: async () => state.list };
    }
    if (url.startsWith("/api/benchmarks/")) {
      const id = url.slice("/api/benchmarks/".length);
      const rep = state.reportById[id];
      if (rep === undefined) {
        return { ok: false, status: 404, json: async () => ({ detail: "benchmark not found" }) };
      }
      return { ok: true, status: 200, json: async () => rep };
    }
    throw new Error(`unexpected request: ${url}`);
  });
}

function renderPage(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetchMock);
  return render(
    <MemoryRouter>
      <BenchmarkPage />
    </MemoryRouter>,
  );
}

async function loaded() {
  await screen.findByRole("heading", { name: "Security Benchmark", level: 1 });
}

function region(name: string) {
  return screen.getByRole("region", { name });
}

function bodyRows(card: HTMLElement): HTMLTableRowElement[] {
  const table = card.querySelector("table");
  if (table === null) throw new Error("no table in card");
  return Array.from(table.querySelectorAll<HTMLTableRowElement>("tbody tr"));
}

function scannerCard(title: string) {
  const card = region(title);
  return {
    value(label: string): string {
      const row = bodyRows(card).find(
        (row) => (row.querySelector("th,td")?.textContent ?? "") === label,
      );
      if (row === undefined) throw new Error(`missing metric row ${label}`);
      return row.querySelectorAll("td")[0]?.textContent ?? "";
    },
  };
}

function statusCard() {
  return region("Benchmark Status");
}

async function loadedReport() {
  await screen.findByRole("region", { name: "Ground Truth" });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("benchmark page renders", () => {
  it("renders the page with title, description, run and refresh actions", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    expect(
      screen.getByText("Controlled comparison of our scanner against Semgrep"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Benchmark" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("refetches the list and report when Refresh is clicked", async () => {
    const onCall = vi.fn();
    renderPage(
      stubApi({
        list: listOf(report()),
        reportById: { [ID_A]: report() },
        onCall,
      }),
    );
    await loaded();
    await loadedReport();
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await loadedReport();
    const listGets = onCall.mock.calls.filter(
      ([url, method]) => String(url) === "/api/benchmarks" && method === "GET",
    );
    expect(listGets.length).toBeGreaterThanOrEqual(2);
  });
});

describe("benchmark status", () => {
  it("shows Completed when Semgrep ran successfully", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    expect(await within(statusCard()).findByText("Completed")).toBeInTheDocument();
  });

  it("shows Semgrep Unavailable when Semgrep did not run", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    const status = within(statusCard());
    expect(await status.findByText("Semgrep Unavailable")).toBeInTheDocument();
    expect(status.getByText(/semgrep CLI not installed/)).toBeInTheDocument();
  });

  it("shows Failed when Semgrep ran but errored", async () => {
    const rep = report({
      semgrep_result: semgrepResult({
        findings: [],
        duration_ms: 900,
        error: "semgrep exited with code 2: boom",
      }),
      metrics: [OUR_METRICS],
    });
    renderPage(stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } }));
    await loaded();
    expect(await within(statusCard()).findByText("Failed")).toBeInTheDocument();
  });
});

describe("ground truth", () => {
  it("renders fixture, case counts, vulnerable and safe counts", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await loadedReport();
    const gt = region("Ground Truth");
    expect(within(gt).getByText("vulnerable_python_app")).toBeInTheDocument();
    expect(within(region("Ground Truth Cases")).getByText("8")).toBeInTheDocument();
    expect(within(region("Vulnerable Cases")).getByText("5")).toBeInTheDocument();
    expect(within(region("Safe Cases")).getByText("3")).toBeInTheDocument();
  });

  it("shows dashes when the ground truth breakdown is not available", async () => {
    const rep = report();
    const list = {
      has_reports: true,
      reports: [{ ...summaryOf(rep), vulnerable_cases: null, safe_cases: null }],
    };
    renderPage(stubApi({ list, reportById: { [ID_A]: rep } }));
    await loaded();
    await screen.findByRole("region", { name: "Ground Truth Cases" });
    expect(within(region("Vulnerable Cases")).getByText("\u2014")).toBeInTheDocument();
    expect(within(region("Safe Cases")).getByText("\u2014")).toBeInTheDocument();
    expect(within(region("Ground Truth Cases")).getByText("8")).toBeInTheDocument();
  });
});

describe("our scanner metrics", () => {
  it("renders findings, TP, FP and FN from the backend metrics", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Our Scanner" });
    const ours = scannerCard("Our Scanner");
    expect(ours.value("Findings")).toBe("5");
    expect(ours.value("True Positives")).toBe("5");
    expect(ours.value("False Positives")).toBe("0");
    expect(ours.value("False Negatives")).toBe("0");
  });

  it("renders precision, recall and F1 as percentages", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Our Scanner" });
    const ours = scannerCard("Our Scanner");
    expect(ours.value("Precision")).toBe("100%");
    expect(ours.value("Recall")).toBe("100%");
    expect(ours.value("F1")).toBe("100%");
  });  it("renders execution time from the backend duration", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Our Scanner" });
    expect(scannerCard("Our Scanner").value("Execution Time")).toBe("4.12s");
  });
});

describe("semgrep metrics", () => {
  it("renders Semgrep metrics when Semgrep ran", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Semgrep" });
    const semgrep = scannerCard("Semgrep");
    expect(semgrep.value("Findings")).toBe("3");
    expect(semgrep.value("True Positives")).toBe("2");
    expect(semgrep.value("False Positives")).toBe("1");
    expect(semgrep.value("False Negatives")).toBe("3");
    expect(semgrep.value("Precision")).toBe("66.67%");
    expect(semgrep.value("Recall")).toBe("40%");
    expect(semgrep.value("F1")).toBe("50%");
    expect(semgrep.value("Execution Time")).toBe("1.90s");
  });

  it("shows the dedicated unavailable state with a reason", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    await screen.findByText("SEMGREP UNAVAILABLE");
    const semgrep = region("Semgrep");
    expect(within(semgrep).getByText("SEMGREP UNAVAILABLE")).toBeInTheDocument();
    expect(
      within(semgrep).getByText("Semgrep is not installed/configured in this environment."),
    ).toBeInTheDocument();
    expect(within(semgrep).getByText(/semgrep CLI not installed/)).toBeInTheDocument();
  });

  it("never displays fake zeros or metrics when Semgrep is unavailable", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    await screen.findByText("SEMGREP UNAVAILABLE");
    const semgrep = region("Semgrep");
    expect(within(semgrep).queryByText("0")).not.toBeInTheDocument();
    expect(within(semgrep).queryByText(/%/)).not.toBeInTheDocument();
    expect(within(semgrep).queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows a failed state when Semgrep ran but errored", async () => {
    const rep = report({
      semgrep_result: semgrepResult({ findings: [], duration_ms: 900, error: "semgrep exited with code 2: boom" }),
      metrics: [OUR_METRICS],
    });
    renderPage(stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } }));
    await loaded();
    await screen.findByText("SEMGREP FAILED");
    const semgrep = region("Semgrep");
    expect(within(semgrep).getByText("SEMGREP FAILED")).toBeInTheDocument();
    expect(within(semgrep).getByText("semgrep exited with code 2: boom")).toBeInTheDocument();
  });
});

describe("metrics comparison", () => {
  it("renders the comparison table with both scanner columns", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    const compare = region("Benchmark Comparison");
    await within(compare).findByRole("table");
    const headers = within(compare).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Metric", "Our Scanner", "Semgrep"]);
    const rows = bodyRows(compare);
    expect(rows).toHaveLength(8);
    expect(rows[0].textContent).toContain("Findings");
    expect(rows[0].textContent).toContain("5");
    expect(rows[0].textContent).toContain("3");
    expect(rows[4].textContent).toContain("Precision");
    expect(rows[4].textContent).toContain("100%");
    expect(rows[4].textContent).toContain("66.67%");
    expect(rows[7].textContent).toContain("Execution Time");
    expect(rows[7].textContent).toContain("4.12s");
    expect(rows[7].textContent).toContain("1.90s");
  });

  it("shows Unavailable in the Semgrep column instead of zeros", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    const compare = region("Benchmark Comparison");
    await within(compare).findByText("Unavailable");
    const rows = bodyRows(compare);
    expect(rows).toHaveLength(8);
    expect(rows[0].textContent).toContain("Unavailable");
    for (const row of rows.slice(1)) {
      expect(row.cells.length).toBe(2);
    }
  });
});

describe("findings comparison", () => {
  it("renders shared, our-only and Semgrep-only findings", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    const findings = region("Findings Comparison");
    await within(findings).findByText("Shared Findings (2)");
    expect(within(findings).getByText("Our Scanner Only (3)")).toBeInTheDocument();
    expect(within(findings).getByText("Semgrep Only (1)")).toBeInTheDocument();
    const tables = Array.from(findings.querySelectorAll("table"));
    expect(tables).toHaveLength(3);
    const sharedRows = tables[0].querySelectorAll("tbody tr");
    expect(sharedRows).toHaveLength(2);
    expect(sharedRows[0].textContent).toContain("sql_injection");
    expect(sharedRows[0].textContent).toContain("app.py");
    expect(sharedRows[0].textContent).toContain("Shared");
    const semgrepOnlyRows = tables[2].querySelectorAll("tbody tr");
    expect(semgrepOnlyRows).toHaveLength(1);
    expect(semgrepOnlyRows[0].textContent).toContain("routes.py");
    expect(semgrepOnlyRows[0].textContent).toContain("Semgrep Only");
  });

  it("shows shared vulnerability types and incorrect safe detections", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    const findings = region("Findings Comparison");
    await within(findings).findByText(/Shared vulnerability types/);
    expect(within(findings).getAllByText("sql_injection").length).toBeGreaterThan(0);
    expect(
      within(findings).getByText(/Safe cases detected incorrectly: sql-app-get-user-safe/),
    ).toBeInTheDocument();
  });

  it("hides the comparison when Semgrep did not run", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    const findings = region("Findings Comparison");
    expect(
      within(findings).getByText("Comparison unavailable because Semgrep did not run."),
    ).toBeInTheDocument();
    expect(within(findings).queryByText(/Shared Findings/)).not.toBeInTheDocument();
  });
});

describe("disclaimer", () => {
  it("renders the disclaimer whenever metrics are displayed", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Our Scanner" });
    expect(
      screen.getByText(
        /Benchmark results are fixture-specific and are not representative of real-world detection accuracy/,
      ),
    ).toBeInTheDocument();
  });
});

describe("empty state", () => {
  it("shows the empty state with explanation and run CTA", async () => {
    renderPage(stubApi({ list: { has_reports: false, reports: [] }, reportById: {} }));
    await loaded();
    expect(screen.getByText("No benchmark results")).toBeInTheDocument();
    expect(
      screen.getByText(/Run the benchmark against the controlled fixture to generate comparison results/),
    ).toBeInTheDocument();
    const empty = region("Benchmark empty state");
    expect(within(empty).getByRole("button", { name: "Run Benchmark" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Run Benchmark" })).toHaveLength(2);
  });

  it("runs the benchmark from the empty state and shows the report", async () => {
    const user = userEvent.setup();
    const rep = report();
    const fetchMock = stubApi({
      list: { has_reports: false, reports: [] },
      reportById: {},
      runResponse: rep,
    });
    renderPage(fetchMock);
    await loaded();
    await user.click(
      within(region("Benchmark empty state")).getByRole("button", { name: "Run Benchmark" }),
    );
    await user.click(
      within(region("Run the benchmark against the controlled fixture?")).getByRole("button", { name: "Run" }),
    );
    await loadedReport();
    const posted = fetchMock.mock.calls.some(
      ([url, init]) => String(url) === "/api/benchmarks/semgrep" && (init as RequestInit)?.method === "POST",
    );
    expect(posted).toBe(true);
    expect(within(region("Our Scanner")).getAllByText("100%").length).toBeGreaterThan(0);
  });
});

describe("loading state", () => {
  it("shows structured skeletons while loading", async () => {
    let resolveList: (value: BenchmarkList) => void = () => {};
    const pending = new Promise<BenchmarkList>((resolve) => {
      resolveList = resolve;
    });
    const rep = report();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/benchmarks") {
        return { ok: true, status: 200, json: async () => pending };
      }
      if (url.startsWith("/api/benchmarks/")) {
        return { ok: true, status: 200, json: async () => rep };
      }
      throw new Error(`unexpected request: ${url}`);
    });
    renderPage(fetchMock);
    await loaded();
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    resolveList(listOf(rep));
    await loadedReport();
    expect(screen.getByRole("region", { name: "Our Scanner" })).toBeInTheDocument();
  });
});

describe("error state", () => {
  it("shows an alert with retry when loading fails, then recovers", async () => {
    const user = userEvent.setup();
    const rep = report();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("network down"))
      .mockImplementation(
        stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } }),
      );
    renderPage(fetchMock);
    await loaded();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to load benchmark results.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await loadedReport();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("benchmark history", () => {
  it("renders runs with id, fixture, created at, status and F1 values", async () => {
    const rep = report();
    renderPage(stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } }));
    await loaded();
    const history = region("Benchmark Runs");
    await within(history).findByRole("table");
    const headers = within(history).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual([
      "Benchmark ID",
      "Fixture",
      "Created At",
      "Status",
      "Our F1",
      "Semgrep F1",
    ]);
    const rows = bodyRows(history);
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain("vulnerable_python_app");
    expect(rows[0].textContent).toContain("Aug 15, 2026");
    expect(rows[0].textContent).toContain("Completed");
    expect(rows[0].textContent).toContain("100%");
    expect(rows[0].textContent).toContain("50%");
  });

  it("loads the selected report when a run is clicked", async () => {
    const user = userEvent.setup();
    const repA = report();
    const repB = reportWithSemgrepUnavailable({
      our_result: {
        ...ourResult(),
        findings: [...OUR_FINDINGS, { ...OUR_FINDINGS[0], fingerprint: "ours-6", line: 99 }],
        duration_ms: 500,
      },
      metrics: [{ ...OUR_METRICS, total_findings: 6 }],
    });
    const fetchMock = stubApi({
      list: listOf(repA, repB),
      reportById: { [ID_A]: repA, [ID_B]: repB },
    });
    renderPage(fetchMock);
    await loaded();
    await loadedReport();
    await user.click(screen.getByRole("button", { name: /View report bbbb/ }));
    await screen.findByText("SEMGREP UNAVAILABLE");
    expect(scannerCard("Our Scanner").value("Findings")).toBe("6");
    expect(screen.getByRole("button", { name: /View report bbbb/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
    const selected = bodyRows(region("Benchmark Runs")).find((row) =>
      row.getAttribute("aria-current") === "true",
    );
    expect(selected?.textContent).toContain("Semgrep Unavailable");
  });

  it("selects a run with the keyboard", async () => {
    const user = userEvent.setup();
    const repA = report();
    const repB = reportWithSemgrepUnavailable({});
    const fetchMock = stubApi({
      list: listOf(repA, repB),
      reportById: { [ID_A]: repA, [ID_B]: repB },
    });
    renderPage(fetchMock);
    await loaded();
    await loadedReport();
    const row = screen.getByRole("button", { name: /View report bbbb/ });
    row.focus();
    await user.keyboard("{Enter}");
    await screen.findByText("SEMGREP UNAVAILABLE");
  });
});

describe("run benchmark flow", () => {
  it("opens a confirmation and cancels without running", async () => {
    const user = userEvent.setup();
    const rep = report();
    const fetchMock = stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } });
    renderPage(fetchMock);
    await loaded();
    await loadedReport();
    await user.click(screen.getByRole("button", { name: "Run Benchmark" }));
    const confirm = region("Run the benchmark against the controlled fixture?");
    expect(within(confirm).getByText(/controlled benchmark against the vulnerable_python_app fixture/)).toBeInTheDocument();
    expect(within(confirm).getByText(/Semgrep must already be installed/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("region", { name: "Run the benchmark against the controlled fixture?" })).not.toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(([url]) => String(url) === "/api/benchmarks/semgrep"),
    ).toBe(false);
  });

  it("runs the benchmark, disables duplicate clicks and shows the new report", async () => {
    const user = userEvent.setup();
    const repA = report();
    const repB = report({ benchmark_id: ID_B, created_at: "2026-08-15T10:00:00Z" });
    let resolveRun: (value: BenchmarkReport) => void = () => {};
    const runResponse = new Promise<BenchmarkReport>((resolve) => {
      resolveRun = resolve;
    });
    const fetchMock = stubApi({
      list: listOf(repA),
      reportById: { [ID_A]: repA },
      runResponse,
    });
    renderPage(fetchMock);
    await loaded();
    await loadedReport();
    await user.click(screen.getByRole("button", { name: "Run Benchmark" }));
    await user.click(
      within(region("Run the benchmark against the controlled fixture?")).getByRole("button", { name: "Run" }),
    );
    expect(await screen.findByRole("button", { name: "Running..." })).toBeDisabled();
    expect(within(statusCard()).getByText("Running")).toBeInTheDocument();
    resolveRun(repB);
    await within(statusCard()).findByText("Completed");
    expect(screen.getByRole("button", { name: /View report bbbb/ })).toBeInTheDocument();
  });

  it("shows an alert when the benchmark run fails", async () => {
    const user = userEvent.setup();
    const rep = report();
    const fetchMock = stubApi({ list: listOf(rep), reportById: { [ID_A]: rep } });
    renderPage(fetchMock);
    await loaded();
    await loadedReport();
    await user.click(screen.getByRole("button", { name: "Run Benchmark" }));
    await user.click(
      within(region("Run the benchmark against the controlled fixture?")).getByRole("button", { name: "Run" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to run the benchmark.");
  });
});

describe("benchmark safety", () => {  it("only ever talks to the backend benchmark API", async () => {
    const onCall = vi.fn();
    const rep = report();
    renderPage(
      stubApi({
        list: listOf(rep),
        reportById: { [ID_A]: rep },
        onCall,
      }),
    );
    await loaded();
    await loadedReport();
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url] of onCall.mock.calls) {
      expect(String(url).startsWith("/api/benchmarks")).toBe(true);
    }
  });

  it("never fabricates finding links to /findings (no invented IDs)", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Findings Comparison" });
    expect(document.body.querySelector('a[href^="/findings"]')).toBeNull();
    expect(
      within(region("Findings Comparison")).queryByRole("link"),
    ).not.toBeInTheDocument();
  });

  it("never fabricates metrics when Semgrep did not run", async () => {
    const rep = reportWithSemgrepUnavailable();
    renderPage(stubApi({ list: listOf(rep), reportById: { [rep.benchmark_id]: rep } }));
    await loaded();
    await screen.findByText("SEMGREP UNAVAILABLE");
    const compare = region("Benchmark Comparison");
    const rows = bodyRows(compare);
    expect(rows).toHaveLength(8);
    expect(rows[0].textContent).toContain("Unavailable");
    for (const row of rows.slice(1)) {
      expect(row.cells.length).toBe(2);
    }
  });
});

describe("responsive and accessibility", () => {
  it("uses a two-column scanner comparison grid with stacked mobile layout", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await loadedReport();
    expect(document.querySelector(".bmk-scanner-grid")).not.toBeNull();
    const css = readFileSync("src/components/benchmark/benchmark.css", "utf-8");
    expect(css).toContain("grid-template-columns: repeat(2, 1fr)");
    expect(css).toContain("@media (max-width: 960px)");
    expect(css).toContain("grid-template-columns: 1fr");
    expect(css).toContain("@media (max-width: 640px)");
  });

  it("exposes semantic tables, labeled regions and text statuses", async () => {
    renderPage(stubApi({ list: listOf(report()), reportById: { [ID_A]: report() } }));
    await loaded();
    await screen.findByRole("region", { name: "Benchmark Status" });
    expect(screen.getAllByRole("table").length).toBeGreaterThan(0);
    for (const name of [
      "Benchmark Status",
      "Ground Truth",
      "Our Scanner",
      "Semgrep",
      "Benchmark Comparison",
      "Findings Comparison",
      "Benchmark Runs",
    ]) {
      expect(screen.getByRole("region", { name })).toBeInTheDocument();
    }
    expect(screen.getAllByText("Completed").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /View report aaaa/ })).toHaveAttribute(
      "aria-current",
      "true",
    );
  });
});
