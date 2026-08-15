import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ProofSummary } from "../api/proof";
import { ProofPage } from "./ProofPage";

const FID1 = "f-sql-1";
const FID2 = "f-cmd-2";
const FID3 = "f-ssrf-3";
const FID4 = "f-path-4";

function summary(overrides: Partial<ProofSummary> = {}): ProofSummary {
  return {
    has_findings: true,
    kpis: {
      total: { available: true, value: 4 },
      verified: { available: true, value: 1 },
      not_verified: { available: true, value: 1 },
      blocked: { available: true, value: 1 },
      errors: { available: true, value: 1 },
    },
    records: [
      {
        finding_id: FID1,
        vulnerability_type: "sql_injection",
        severity: "critical",
        priority: "P0",
        validation: "true_positive",
        status: "verified",
        confidence: 0.9,
        duration_ms: 1420,
        created_at: "2026-08-15T09:00:00Z",
        summary: "Request reaches the sink inside the sandboxed harness",
        error: null,
        repository: "repo-a",
        file: "users.py",
        sandbox_policy: {
          network_enabled: false,
          allow_loopback: false,
          timeout_seconds: 10,
          max_output_bytes: 16384,
          max_processes: 1,
        },
      },
      {
        finding_id: FID2,
        vulnerability_type: "command_injection",
        severity: "high",
        priority: "P1",
        validation: "true_positive",
        status: "not_verified",
        confidence: 0.6,
        duration_ms: 850,
        created_at: "2026-08-15T08:00:00Z",
        summary: "Sink is not reachable from the supplied source",
        error: null,
        repository: "repo-a",
        file: "cli.py",
        sandbox_policy: {
          network_enabled: false,
          allow_loopback: false,
          timeout_seconds: 10,
          max_output_bytes: 16384,
          max_processes: 1,
        },
      },
      {
        finding_id: FID3,
        vulnerability_type: "ssrf",
        severity: "medium",
        priority: "P2",
        validation: "uncertain",
        status: "blocked",
        confidence: 0.4,
        duration_ms: 5000,
        created_at: "2026-08-15T07:00:00Z",
        summary: null,
        error: null,
        repository: "repo-b",
        file: "net.py",
        sandbox_policy: {
          network_enabled: false,
          allow_loopback: true,
          timeout_seconds: 10,
          max_output_bytes: 16384,
          max_processes: 1,
        },
      },
      {
        finding_id: FID4,
        vulnerability_type: "path_traversal",
        severity: "medium",
        priority: null,
        validation: null,
        status: "error",
        confidence: 0.2,
        duration_ms: 200,
        created_at: "2026-08-15T06:00:00Z",
        summary: "Harness failed before reaching the sink",
        error: "sandbox rejected the harness",
        repository: "repo-b",
        file: "paths.py",
        sandbox_policy: null,
      },
    ],
    ...overrides,
  };
}

function stubApi(data: ProofSummary, onCall?: (url: string) => void) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    onCall?.(url);
    if (url === "/api/proof") {
      return { ok: true, status: 200, json: async () => data };
    }
    throw new Error(`unexpected request: ${url}`);
  });
}

function LocationProbe() {
  const { search } = useLocation();
  return <div data-testid="router-search">{search}</div>;
}

function renderPage(initialEntry = "/proof", fetchMock?: ReturnType<typeof vi.fn>) {
  if (fetchMock) {
    vi.stubGlobal("fetch", fetchMock);
  } else {
    vi.stubGlobal("fetch", stubApi(summary()));
  }
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <Routes>
        <Route path="/proof" element={<ProofPage />} />
        <Route path="/findings/:id" element={<div>finding-detail-stub</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function loaded() {
  await screen.findByRole("heading", { name: "Proof", level: 1 });
}

function kpi(label: string) {
  return screen.getByRole("region", { name: label });
}

function filterSelect(label: string) {
  return screen.getByRole("combobox", { name: label });
}

function searchInput() {
  return screen.getByRole("searchbox", { name: "Search proofs" });
}

function tableRows(): HTMLElement[] {
  const region = screen.getByRole("region", { name: "Proof Results" });
  const table = region.querySelector("table");
  if (table === null) throw new Error("no table inside Proof Results");
  return Array.from(
    table.querySelectorAll<HTMLTableRowElement>("tbody tr"),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("proof page renders", () => {
  it("renders the page with title, description and refresh action", async () => {
    renderPage();
    await loaded();
    expect(
      screen.getByText("Sandboxed verification results for validated findings"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("refetches the summary when Refresh is clicked", async () => {
    const fetchMock = stubApi(summary());
    renderPage("/proof", fetchMock);
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("region", { name: "Proof Results" });
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe("proof KPI cards", () => {
  it("renders the five KPI cards with real values", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Total Proof Results" });
    expect(within(kpi("Total Proof Results")).getByText("4")).toBeInTheDocument();
    expect(within(kpi("Verified")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Not Verified")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Blocked")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Errors")).getByText("1")).toBeInTheDocument();
  });

  it("shows a dash instead of fabricated numbers when data is unavailable", async () => {
    renderPage(
      "/proof",
      stubApi(
        summary({
          has_findings: true,
          kpis: {
            total: { available: false, value: 0 },
            verified: { available: false, value: 0 },
            not_verified: { available: false, value: 0 },
            blocked: { available: false, value: 0 },
            errors: { available: false, value: 0 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    await screen.findByRole("region", { name: "Total Proof Results" });
    expect(within(kpi("Total Proof Results")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Verified")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Not Verified")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Blocked")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Errors")).getByText("\u2014")).toBeInTheDocument();
  });
});

describe("proof table", () => {
  it("renders the table with all columns and rows", async () => {
    renderPage();
    await loaded();
    const region = await screen.findByRole("region", { name: "Proof Results" });
    const table = region.querySelector("table") as HTMLElement;
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual([
      "Finding",
      "Vulnerability",
      "Priority",
      "Validation",
      "Proof Status",
      "Confidence",
      "Duration",
      "Created At",
      "Summary",
    ]);
    const rows = tableRows();
    expect(rows).toHaveLength(4);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
    expect(within(rows[0]).getByText("VERIFIED")).toBeInTheDocument();
    expect(within(rows[1]).getByText("NOT VERIFIED")).toBeInTheDocument();
    expect(within(rows[2]).getByText("BLOCKED")).toBeInTheDocument();
    expect(within(rows[3]).getByText("ERROR")).toBeInTheDocument();
  });

  it("displays proof status with text and badge", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const rows = tableRows();
    expect(within(rows[0]).getByText("VERIFIED")).toBeInTheDocument();
    expect(within(rows[1]).getByText("NOT VERIFIED")).toBeInTheDocument();
    expect(within(rows[2]).getByText("BLOCKED")).toBeInTheDocument();
    expect(within(rows[3]).getByText("ERROR")).toBeInTheDocument();
  });

  it("displays the backend duration as a human-readable value", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const rows = tableRows();
    expect(within(rows[0]).getByText("1.42s")).toBeInTheDocument();
    expect(within(rows[1]).getByText("850ms")).toBeInTheDocument();
    expect(within(rows[2]).getByText("5.00s")).toBeInTheDocument();
    expect(within(rows[3]).getByText("200ms")).toBeInTheDocument();
  });

  it("shows the validation verdict per record", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const rows = tableRows();
    expect(within(rows[0]).getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(within(rows[2]).getByText("UNCERTAIN")).toBeInTheDocument();
    expect(within(rows[3]).getAllByText("\u2014")).toHaveLength(2);
  });

  it("renders rows in the backend-provided order", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const rows = tableRows();
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
    expect(within(rows[1]).getByText("command_injection")).toBeInTheDocument();
    expect(within(rows[2]).getByText("ssrf")).toBeInTheDocument();
    expect(within(rows[3]).getByText("path_traversal")).toBeInTheDocument();
  });
});

describe("proof summary and sandbox policy", () => {
  it("shows the stored proof summary", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(
      screen.getByText("Request reaches the sink inside the sandboxed harness"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Sink is not reachable from the supplied source"),
    ).toBeInTheDocument();
  });

  it("shows the sandbox policy fields returned by the backend", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(screen.getAllByText("Sandbox Policy").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Network").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Disabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("10s").length).toBeGreaterThan(0);
    expect(screen.getAllByText("1").length).toBeGreaterThan(0);
  });

  it("does not show a sandbox policy when the backend has none", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const rows = tableRows();
    const last = within(rows[3]);
    expect(last.queryByText("Network")).not.toBeInTheDocument();
  });

  it("handles missing summaries", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(
      screen.getAllByText("No proof summary available"),
    ).toHaveLength(1);
  });

  it("shows the backend error message for failed proofs", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(screen.getByText("sandbox rejected the harness")).toBeInTheDocument();
  });
});

describe("proof filters", () => {
  it("filters the table by proof status", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.selectOptions(filterSelect("Proof Status"), "BLOCKED");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("ssrf")).toBeInTheDocument();
  });

  it("filters the table by priority", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.selectOptions(filterSelect("Priority"), "P1");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("command_injection")).toBeInTheDocument();
  });

  it("filters the table by severity", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.selectOptions(filterSelect("Severity"), "critical");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
  });

  it("filters the table by validation verdict", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.selectOptions(filterSelect("Validation Verdict"), "UNCERTAIN");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("ssrf")).toBeInTheDocument();
  });

  it("searches across finding, vulnerability, repository and file", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.type(searchInput(), "paths.py");
    expect(tableRows()).toHaveLength(1);
    expect(tableRows()[0].textContent).toContain("path_traversal");
    await user.clear(searchInput());
    await user.type(searchInput(), "COMMAND");
    expect(tableRows()).toHaveLength(1);
    expect(tableRows()[0].textContent).toContain("command_injection");
    await user.clear(searchInput());
    await user.type(searchInput(), "f-sql-1");
    expect(tableRows()).toHaveLength(1);
    expect(tableRows()[0].textContent).toContain("sql_injection");
  });

  it("initializes filters from URL query parameters", async () => {
    renderPage("/proof?status=ERROR&severity=medium");
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(filterSelect("Proof Status")).toHaveValue("ERROR");
    expect(filterSelect("Severity")).toHaveValue("medium");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("path_traversal")).toBeInTheDocument();
  });

  it("persists the status filter to the URL", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.selectOptions(filterSelect("Proof Status"), "VERIFIED");
    expect(screen.getByTestId("router-search").textContent).toContain(
      "status=VERIFIED",
    );
  });
});

describe("proof navigation", () => {
  it("navigates to the finding detail from the finding link", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    await user.click(screen.getByRole("link", { name: "f-sql-1" }));
    expect(await screen.findByText("finding-detail-stub")).toBeInTheDocument();
  });

  it("navigates to the finding detail from a row click", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("link", { name: "Open finding sql_injection" });
    await user.click(
      screen.getByRole("link", { name: "Open finding sql_injection" }),
    );
    expect(await screen.findByText("finding-detail-stub")).toBeInTheDocument();
  });
});

describe("proof states", () => {
  it("shows the empty state when nothing has been scanned", async () => {
    renderPage(
      "/proof",
      stubApi(
        summary({
          has_findings: false,
          kpis: {
            total: { available: false, value: 0 },
            verified: { available: false, value: 0 },
            not_verified: { available: false, value: 0 },
            blocked: { available: false, value: 0 },
            errors: { available: false, value: 0 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    expect(screen.getByText("No proof results")).toBeInTheDocument();
    expect(
      screen.getByText(/Proof results will appear after the proof stage/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows an empty message when there are no proof records", async () => {
    renderPage(
      "/proof",
      stubApi(
        summary({
          has_findings: true,
          kpis: {
            total: { available: false, value: 0 },
            verified: { available: false, value: 0 },
            not_verified: { available: false, value: 0 },
            blocked: { available: false, value: 0 },
            errors: { available: false, value: 0 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    const region = await screen.findByRole("region", { name: "Proof Results" });
    expect(within(region).getByText("No proof results")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Open finding/ })).not.toBeInTheDocument();
  });

  it("shows structured skeletons while loading", async () => {
    let resolveData: (value: ProofSummary) => void = () => {};
    const pending = new Promise<ProofSummary>((resolve) => {
      resolveData = resolve;
    });
    const fetchMock = vi.fn(async () => {
      return { ok: true, status: 200, json: async () => pending };
    });
    renderPage("/proof", fetchMock);
    await loaded();
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    resolveData(summary());
    await screen.findByRole("region", { name: "Proof Results" });
    expect(tableRows().length).toBeGreaterThan(0);
  });

  it("shows an alert with retry when loading fails, then recovers", async () => {
    const user = userEvent.setup();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("network down"))
      .mockImplementation(stubApi(summary()));
    renderPage("/proof", fetchMock);
    await loaded();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to load proof results.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("region", { name: "Proof Results" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("proof safety", () => {
  it("never displays dangerous execution details", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const body = document.body.textContent ?? "";
    expect(body).not.toMatch(/subprocess/i);
    expect(body).not.toMatch(/payload/i);
    expect(body).not.toMatch(/raw command/i);
    expect(body).not.toMatch(/artifact/i);
    expect(body).not.toMatch(/api key|secret|credential/i);
  });

  it("is read-only: no execution, shell or proof controls", async () => {
    const fetchMock = stubApi(summary());
    renderPage("/proof", fetchMock);
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    const buttons = screen.getAllByRole("button").map((b) => b.textContent);
    expect(buttons).toEqual(["Refresh"]);
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(1);
    for (const call of fetchMock.mock.calls) {
      expect(String(call[0])).toBe("/api/proof");
    }
  });

  it("never invents proof records", async () => {
    renderPage(
      "/proof",
      stubApi(
        summary({
          has_findings: true,
          records: [],
          kpis: {
            total: { available: false, value: 0 },
            verified: { available: false, value: 0 },
            not_verified: { available: false, value: 0 },
            blocked: { available: false, value: 0 },
            errors: { available: false, value: 0 },
          },
        }),
      ),
    );
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(screen.queryByText("VERIFIED")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Open finding/ })).not.toBeInTheDocument();
  });
});

describe("proof accessibility", () => {
  it("provides labeled filters, semantic tables and labeled cards", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Proof Results" });
    expect(screen.getByRole("combobox", { name: "Proof Status" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Priority" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Severity" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Validation Verdict" })).toBeInTheDocument();
    const tables = screen.getAllByRole("table");
    for (const table of tables) {
      expect(within(table).getAllByRole("columnheader").length).toBeGreaterThan(0);
    }
    expect(screen.getByRole("region", { name: "Total Proof Results" })).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /Open finding/ }).length).toBe(4);
  });
});
