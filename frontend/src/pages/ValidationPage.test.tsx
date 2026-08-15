import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ValidationSummary } from "../api/validation";
import { ValidationPage } from "./ValidationPage";

const FID1 = "f-sql-1";
const FID2 = "f-cmd-2";
const FID3 = "f-ssrf-3";

function summary(overrides: Partial<ValidationSummary> = {}): ValidationSummary {
  return {
    has_findings: true,
    kpis: {
      total_validations: { available: true, value: 3 },
      true_positives: { available: true, value: 1 },
      false_positives: { available: true, value: 1 },
      uncertain: { available: true, value: 1 },
      pending: { available: true, value: 0 },
    },
    records: [
      {
        finding_id: FID1,
        vulnerability_type: "sql_injection",
        severity: "critical",
        priority: "P0",
        repository: "repo-a",
        file: "users.py",
        confidence: 0.94,
        verdict: "true_positive",
        reasoning: "tainted value reaches the sink through the supplied path",
        evidence_used: ["taint_path", "sink_snippet"],
        validated_at: "2026-08-15T09:00:00Z",
        proof_status: "verified",
      },
      {
        finding_id: FID2,
        vulnerability_type: "command_injection",
        severity: "high",
        priority: "P1",
        repository: "repo-a",
        file: "cli.py",
        confidence: 0.81,
        verdict: "false_positive",
        reasoning: "input is sanitized before the sink",
        evidence_used: [],
        validated_at: "2026-08-15T08:00:00Z",
        proof_status: null,
      },
      {
        finding_id: FID3,
        vulnerability_type: "ssrf",
        severity: "medium",
        priority: "P2",
        repository: "repo-b",
        file: "net.py",
        confidence: null,
        verdict: "uncertain",
        reasoning: null,
        evidence_used: [],
        validated_at: "2026-08-15T07:00:00Z",
        proof_status: "blocked",
      },
    ],
    ...overrides,
  };
}

function stubApi(data: ValidationSummary, onCall?: (url: string) => void) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    onCall?.(url);
    if (url === "/api/validation") {
      return { ok: true, status: 200, json: async () => data };
    }
    throw new Error(`unexpected request: ${url}`);
  });
}

function LocationProbe() {
  const { search } = useLocation();
  return <div data-testid="router-search">{search}</div>;
}

function renderPage(initialEntry = "/validation", fetchMock?: ReturnType<typeof vi.fn>) {
  if (fetchMock) {
    vi.stubGlobal("fetch", fetchMock);
  } else {
    vi.stubGlobal("fetch", stubApi(summary()));
  }
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <Routes>
        <Route path="/validation" element={<ValidationPage />} />
        <Route path="/findings/:id" element={<div>finding-detail-stub</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function loaded() {
  await screen.findByRole("heading", { name: "Validation", level: 1 });
}

function kpi(label: string) {
  return screen.getByRole("region", { name: label });
}

function filterSelect(label: string) {
  return screen.getByRole("combobox", { name: label });
}

function searchInput() {
  return screen.getByRole("searchbox", { name: "Search validations" });
}

function tableRows(): HTMLElement[] {
  const region = screen.getByRole("region", { name: "Validation Results" });
  const table = region.querySelector("table");
  if (table === null) throw new Error("no table inside Validation Results");
  return Array.from(
    table.querySelectorAll<HTMLTableRowElement>("tbody tr"),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("validation page renders", () => {
  it("renders the page with title, description and refresh action", async () => {
    renderPage();
    await loaded();
    expect(
      screen.getByText("LLM-assisted validation of detected security findings"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("refetches the summary when Refresh is clicked", async () => {
    const fetchMock = stubApi(summary());
    renderPage("/validation", fetchMock);
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await screen.findByRole("region", { name: "Validation Results" });
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe("validation KPI cards", () => {
  it("renders the five KPI cards with real values", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Total Validations" });
    expect(within(kpi("Total Validations")).getByText("3")).toBeInTheDocument();
    expect(within(kpi("True Positives")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("False Positives")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Uncertain")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Pending / Not Validated")).getByText("0")).toBeInTheDocument();
  });

  it("shows a dash instead of fabricated numbers when data is unavailable", async () => {
    renderPage(
      "/validation",
      stubApi(
        summary({
          has_findings: true,
          kpis: {
            total_validations: { available: false, value: 0 },
            true_positives: { available: false, value: 0 },
            false_positives: { available: false, value: 0 },
            uncertain: { available: false, value: 0 },
            pending: { available: true, value: 3 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    await screen.findByRole("region", { name: "Total Validations" });
    expect(within(kpi("Total Validations")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("True Positives")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("False Positives")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Uncertain")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Pending / Not Validated")).getByText("3")).toBeInTheDocument();
  });
});

describe("validation table", () => {
  it("renders the table with all columns and rows", async () => {
    renderPage();
    await loaded();
    const region = await screen.findByRole("region", { name: "Validation Results" });
    const table = region.querySelector("table") as HTMLElement;
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual([
      "Finding",
      "Vulnerability",
      "Severity",
      "Priority",
      "Confidence",
      "Verdict",
      "Validated At",
      "Proof Status",
      "Reasoning",
    ]);
    const rows = tableRows();
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
    expect(within(rows[0]).getByText("94%")).toBeInTheDocument();
    expect(within(rows[0]).getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(within(rows[0]).getByText("VERIFIED")).toBeInTheDocument();
    expect(within(rows[1]).getByText("FALSE POSITIVE")).toBeInTheDocument();
    expect(within(rows[2]).getByText("UNCERTAIN")).toBeInTheDocument();
    expect(within(rows[2]).getByText("\u2014")).toBeInTheDocument();
    expect(within(rows[2]).getByText("BLOCKED")).toBeInTheDocument();
  });

  it("displays the validation confidence and verdict with text and badge", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    const rows = tableRows();
    const first = within(rows[0]);
    expect(first.getByText("94%")).toBeInTheDocument();
    expect(first.getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(first.getByText("VERIFIED")).toBeInTheDocument();
  });

  it("shows a dash for absent confidence", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    const rows = tableRows();
    expect(within(rows[2]).getByText("\u2014")).toBeInTheDocument();
    expect(within(rows[2]).queryByText(/\d+%/)).not.toBeInTheDocument();
  });

  it("renders rows in the backend-provided order", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    const rows = tableRows();
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
    expect(within(rows[1]).getByText("command_injection")).toBeInTheDocument();
    expect(within(rows[2]).getByText("ssrf")).toBeInTheDocument();
  });
});

describe("validation reasoning", () => {
  it("shows the stored reasoning for a record", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    const rows = tableRows();
    const reasoning = within(rows[0]).getByText("Reasoning");
    expect(reasoning).toBeInTheDocument();
    expect(
      screen.getByText("tainted value reaches the sink through the supplied path"),
    ).toBeInTheDocument();
  });

  it("shows the evidence-used section when evidence exists", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    expect(screen.getByText("Evidence used")).toBeInTheDocument();
    expect(screen.getByText("taint_path")).toBeInTheDocument();
    expect(screen.getByText("sink_snippet")).toBeInTheDocument();
  });

  it("does not show an evidence section when no evidence was used", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    expect(screen.getAllByText("Evidence used")).toHaveLength(1);
  });

  it("handles missing reasoning", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    expect(
      screen.getAllByText("No validation reasoning available"),
    ).toHaveLength(1);
  });
});

describe("validation filters", () => {
  it("filters the table by verdict", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await user.selectOptions(filterSelect("Verdict"), "TRUE POSITIVE");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
  });

  it("filters the table by severity", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await user.selectOptions(filterSelect("Severity"), "high");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("command_injection")).toBeInTheDocument();
  });

  it("filters the table by priority", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await user.selectOptions(filterSelect("Priority"), "P0");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
  });

  it("searches across finding, vulnerability, repository and file", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await user.type(searchInput(), "repo-b");
    expect(tableRows()).toHaveLength(1);
    expect(tableRows()[0].textContent).toContain("ssrf");
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
    renderPage("/validation?verdict=UNCERTAIN&priority=P2");
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    expect(filterSelect("Verdict")).toHaveValue("UNCERTAIN");
    expect(filterSelect("Priority")).toHaveValue("P2");
    const rows = tableRows();
    expect(rows).toHaveLength(1);
    expect(within(rows[0]).getByText("ssrf")).toBeInTheDocument();
  });

  it("persists the verdict filter to the URL", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    await user.selectOptions(filterSelect("Verdict"), "FALSE POSITIVE");
    expect(screen.getByTestId("router-search").textContent).toContain(
      "verdict=FALSE+POSITIVE",
    );
  });
});

describe("validation navigation", () => {
  it("navigates to the finding detail from the finding link", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
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

describe("validation states", () => {
  it("shows the empty state when nothing has been scanned", async () => {
    renderPage(
      "/validation",
      stubApi(
        summary({
          has_findings: false,
          kpis: {
            total_validations: { available: false, value: 0 },
            true_positives: { available: false, value: 0 },
            false_positives: { available: false, value: 0 },
            uncertain: { available: false, value: 0 },
            pending: { available: false, value: 0 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    expect(screen.getByText("No validation results")).toBeInTheDocument();
    expect(
      screen.getByText(/Validation results will appear after findings/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows an empty message when there are no validation records", async () => {
    renderPage(
      "/validation",
      stubApi(
        summary({
          has_findings: true,
          kpis: {
            total_validations: { available: false, value: 0 },
            true_positives: { available: false, value: 0 },
            false_positives: { available: false, value: 0 },
            uncertain: { available: false, value: 0 },
            pending: { available: true, value: 3 },
          },
          records: [],
        }),
      ),
    );
    await loaded();
    const region = await screen.findByRole("region", { name: "Validation Results" });
    expect(within(region).getByText("No validation results")).toBeInTheDocument();
    expect(within(kpi("Pending / Not Validated")).getByText("3")).toBeInTheDocument();
  });

  it("shows structured skeletons while loading", async () => {
    let resolveData: (value: ValidationSummary) => void = () => {};
    const pending = new Promise<ValidationSummary>((resolve) => {
      resolveData = resolve;
    });
    const fetchMock = vi.fn(async () => {
      return { ok: true, status: 200, json: async () => pending };
    });
    renderPage("/validation", fetchMock);
    await loaded();
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    resolveData(summary());
    await screen.findByRole("region", { name: "Validation Results" });
    expect(tableRows().length).toBeGreaterThan(0);
  });

  it("shows an alert with retry when loading fails, then recovers", async () => {
    const user = userEvent.setup();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("network down"))
      .mockImplementation(stubApi(summary()));
    renderPage("/validation", fetchMock);
    await loaded();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to load validation results.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("region", { name: "Validation Results" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("validation safety", () => {
  it("is read-only: no validation, execution or remediation controls", async () => {
    const fetchMock = stubApi(summary());
    renderPage("/validation", fetchMock);
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    const buttons = screen.getAllByRole("button").map((b) => b.textContent);
    expect(buttons).toEqual(["Refresh"]);
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(1);
    for (const call of fetchMock.mock.calls) {
      expect(String(call[0])).toBe("/api/validation");
    }
  });

  it("never invents validation records", async () => {
    renderPage(
      "/validation",
      stubApi(
        summary({
          has_findings: true,
          records: [],
          kpis: {
            ...summary().kpis,
            total_validations: { available: false, value: 0 },
            true_positives: { available: false, value: 0 },
            false_positives: { available: false, value: 0 },
            uncertain: { available: false, value: 0 },
            pending: { available: true, value: 3 },
          },
        }),
      ),
    );
    await loaded();
    await screen.findByRole("region", { name: "Validation Results" });
    expect(screen.queryByText("TRUE POSITIVE")).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Open finding/ })).not.toBeInTheDocument();
  });
});
