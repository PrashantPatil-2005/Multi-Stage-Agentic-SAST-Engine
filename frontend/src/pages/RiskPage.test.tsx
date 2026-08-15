import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RiskSummary } from "../api/risk";
import { RiskPage } from "./RiskPage";

const FID1 = "f-sql-1";
const FID2 = "f-cmd-2";
const FID3 = "f-ssrf-3";

function summary(overrides: Partial<RiskSummary> = {}): RiskSummary {
  return {
    has_findings: true,
    kpis: {
      total_assessments: { available: true, value: 3 },
      critical_p0: { available: true, value: 2 },
      high_p1: { available: true, value: 1 },
      active_slas: { available: true, value: 2 },
      sla_breaches: { available: true, value: 1 },
      escalations: { available: true, value: 2 },
    },
    priority_distribution: [
      { priority: "P0", count: 2, percent: 67 },
      { priority: "P1", count: 1, percent: 33 },
      { priority: "P2", count: 1, percent: 33 },
    ],
    risk_distribution: [
      { label: "61-80", count: 1, percent: 33 },
      { label: "81-100", count: 2, percent: 67 },
    ],
    highest_risk_findings: [
      {
        finding_id: FID1,
        priority: "P0",
        risk_score: 95,
        severity: "critical",
        vulnerability_type: "sql_injection",
        repository: "repo-a",
        file: "users.py",
        validation: "true_positive",
        proof: "verified",
        sla: "active",
        factors: [
          { name: "severity", value: "critical", points: 75, description: "base severity weight" },
          { name: "validation", value: "true_positive", points: 10, description: "validated" },
          { name: "proof", value: "verified", points: 10, description: "proven" },
        ],
      },
      {
        finding_id: FID2,
        priority: "P1",
        risk_score: 75,
        severity: "high",
        vulnerability_type: "command_injection",
        repository: "repo-a",
        file: "cli.py",
        validation: null,
        proof: null,
        sla: "breached",
        factors: [],
      },
      {
        finding_id: FID3,
        priority: "P2",
        risk_score: 65,
        severity: "medium",
        vulnerability_type: "ssrf",
        repository: "repo-b",
        file: "net.py",
        validation: null,
        proof: null,
        sla: "none",
        factors: [],
      },
    ],
    sla_overview: { available: true, active: 2, breached: 1, resolved: 1, no_sla: 1 },
    active_slas: [
      {
        finding_id: FID1,
        vulnerability_type: "sql_injection",
        priority: "P0",
        started_at: "2026-08-15T05:00:00Z",
        due_at: "2026-08-15T09:00:00Z",
        status: "active",
        escalation_level: 0,
        breached_at: null,
        remaining_seconds: 45000,
      },
      {
        finding_id: FID4,
        vulnerability_type: "path_traversal",
        priority: "P1",
        started_at: "2026-08-15T08:00:00Z",
        due_at: "2026-08-16T08:00:00Z",
        status: "active",
        escalation_level: 0,
        breached_at: null,
        remaining_seconds: 1500,
      },
    ],
    breaches: [
      {
        finding_id: FID2,
        vulnerability_type: "command_injection",
        priority: "P1",
        started_at: "2026-08-14T09:00:00Z",
        due_at: "2026-08-15T09:00:00Z",
        status: "breached",
        escalation_level: 1,
        breached_at: "2026-08-15T09:05:00Z",
        remaining_seconds: null,
      },
    ],
    escalations: [
      {
        finding_id: FID2,
        previous_level: 0,
        new_level: 2,
        reason: "SLA deadline exceeded for command_injection",
        created_at: "2026-08-15T09:05:00Z",
        vulnerability_type: "command_injection",
        priority: "P1",
      },
      {
        finding_id: FID1,
        previous_level: 0,
        new_level: 1,
        reason: "SLA deadline exceeded for sql_injection",
        created_at: "2026-08-15T08:00:00Z",
        vulnerability_type: "sql_injection",
        priority: "P0",
      },
    ],
    ...overrides,
  };
}

const FID4 = "f-path-4";

function LocationProbe() {
  const { search } = useLocation();
  return <div data-testid="router-search">{search}</div>;
}

function stubApi(data: RiskSummary, onCall?: (url: string) => void) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    onCall?.(url);
    if (url === "/api/risk/summary") {
      return { ok: true, status: 200, json: async () => data };
    }
    throw new Error(`unexpected request: ${url}`);
  });
}

function renderPage(initialEntry = "/risk", fetchMock?: ReturnType<typeof vi.fn>) {
  if (fetchMock) {
    vi.stubGlobal("fetch", fetchMock);
  } else {
    vi.stubGlobal("fetch", stubApi(summary()));
  }
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationProbe />
      <Routes>
        <Route path="/risk" element={<RiskPage />} />
        <Route path="/findings/:id" element={<div>finding-detail-stub</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function loaded() {
  await screen.findByRole("heading", { name: "Risk & SLA", level: 1 });
}

function kpi(label: string) {
  return screen.getByRole("region", { name: label });
}

function filterSelect(label: string) {
  return screen.getByRole("combobox", { name: label });
}

function sectionTable(sectionLabel: string): HTMLElement {
  const region = screen.getByRole("region", { name: sectionLabel });
  const table = region.querySelector("table");
  if (table === null) throw new Error(`no table inside ${sectionLabel}`);
  return table as HTMLElement;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("risk page renders", () => {
  it("renders the page with title, description and refresh action", async () => {
    renderPage();
    await loaded();
    expect(
      screen.getByText("Prioritize security findings and track remediation deadlines"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("refetches the summary when Refresh is clicked", async () => {
    const fetchMock = stubApi(summary());
    renderPage("/risk", fetchMock);
    await loaded();
    const table = await screen.findByRole("region", { name: "Highest Risk Findings" }).then((r) => r.querySelector("table") as HTMLElement);
    await within(table).findByText("sql_injection");
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await within(table).findByText("sql_injection");
    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe("KPI cards", () => {
  it("renders the six KPI cards with real values", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Total Risk Assessments" });
    expect(within(kpi("Total Risk Assessments")).getByText("3")).toBeInTheDocument();
    expect(within(kpi("Critical / P0")).getByText("2")).toBeInTheDocument();
    expect(within(kpi("High / P1")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Active SLAs")).getByText("2")).toBeInTheDocument();
    expect(within(kpi("SLA Breaches")).getByText("1")).toBeInTheDocument();
    expect(within(kpi("Escalations")).getByText("2")).toBeInTheDocument();
  });

  it("shows a dash instead of fabricated numbers when data is unavailable", async () => {
    renderPage(
      "/risk",
      stubApi(
        summary({
          has_findings: true,
          kpis: {
            total_assessments: { available: false, value: 0 },
            critical_p0: { available: false, value: 0 },
            high_p1: { available: false, value: 0 },
            active_slas: { available: false, value: 0 },
            sla_breaches: { available: false, value: 0 },
            escalations: { available: false, value: 0 },
          },
          priority_distribution: [],
          risk_distribution: [],
          highest_risk_findings: [],
        }),
      ),
    );
    await loaded();
    await screen.findByRole("region", { name: "Total Risk Assessments" });
    expect(within(kpi("Total Risk Assessments")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Critical / P0")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Active SLAs")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("SLA Breaches")).getByText("\u2014")).toBeInTheDocument();
    expect(within(kpi("Escalations")).getByText("\u2014")).toBeInTheDocument();
  });
});

describe("distributions", () => {
  it("renders the priority distribution with counts and percentages", async () => {
    renderPage();
    await loaded();
    const card = screen.getByRole("region", { name: "Priority Distribution" });
    expect(within(card).getByText("P0")).toBeInTheDocument();
    expect(
      within(card).getAllByText("1 finding \u00b7 33%").length,
    ).toBeGreaterThanOrEqual(1);
    expect(within(card).getByText("P1")).toBeInTheDocument();
    expect(within(card).getByText("P2")).toBeInTheDocument();
    expect(
      within(card).getByRole("img", { name: "P0 — 2 findings (67%)" }),
    ).toBeInTheDocument();
  });

  it("renders the risk score distribution", async () => {
    renderPage();
    await loaded();
    const card = screen.getByRole("region", { name: "Risk Distribution" });
    expect(within(card).getByText("61-80")).toBeInTheDocument();
    expect(within(card).getByText("81-100")).toBeInTheDocument();
    expect(within(card).getByText("2 findings \u00b7 67%")).toBeInTheDocument();
  });

  it("shows an empty message instead of fake charts when no assessments exist", async () => {
    renderPage(
      "/risk",
      stubApi(
        summary({
          priority_distribution: [],
          risk_distribution: [],
          highest_risk_findings: [],
        }),
      ),
    );
    await loaded();
    expect(
      screen.getAllByText("No risk assessments available").length,
    ).toBeGreaterThanOrEqual(2);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });
});

describe("highest risk findings", () => {
  it("renders the table with all columns and rows", async () => {
    renderPage();
    await loaded();
    const table = sectionTable("Highest Risk Findings");
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual([
      "Priority",
      "Risk Score",
      "Severity",
      "Vulnerability",
      "Repository",
      "File",
      "Validation",
      "Proof",
      "SLA",
    ]);
    const rows = Array.from(table.querySelectorAll<HTMLTableRowElement>("tbody tr"));
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("sql_injection")).toBeInTheDocument();
    expect(within(rows[0]).getByText("95")).toBeInTheDocument();
    expect(within(rows[0]).getByText("True Positive")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Verified")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Active")).toBeInTheDocument();
    expect(within(rows[1]).getByText("command_injection")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Breached")).toBeInTheDocument();
    expect(within(rows[2]).getByText("ssrf")).toBeInTheDocument();
    expect(within(rows[2]).getAllByText("\u2014").length).toBeGreaterThan(0);
  });

  it("renders rows in the backend-provided order (highest priority, then score)", async () => {
    renderPage();
    await loaded();
    const region = await screen.findByRole("region", { name: "Highest Risk Findings" });
    const rows = Array.from(region.querySelectorAll<HTMLTableRowElement>("tbody tr"));
    const first = within(rows[0]);
    expect(first.getByText("P0")).toBeInTheDocument();
    expect(first.getByText("95")).toBeInTheDocument();
    expect(within(rows[1]).getByText("P1")).toBeInTheDocument();
  });

  it("navigates to the finding detail from a row link", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    const region = await screen.findByRole("region", { name: "Highest Risk Findings" });
    await user.click(within(region).getByRole("link", { name: "sql_injection" }));
    expect(await screen.findByText("finding-detail-stub")).toBeInTheDocument();
  });

  it("navigates to the finding detail from a row click", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    const row = await screen.findByRole("link", { name: "Open finding sql_injection" });
    await user.click(row);
    expect(await screen.findByText("finding-detail-stub")).toBeInTheDocument();
  });

  it("opens the finding with the keyboard", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    const row = await screen.findByRole("link", { name: "Open finding command_injection" });
    row.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByText("finding-detail-stub")).toBeInTheDocument();
  });

  it("shows a compact risk factor summary for the highest-risk finding", async () => {
    renderPage();
    await loaded();
    const section = screen.getByLabelText("Risk factors for the top finding");
    expect(within(section).getByText("Risk Factors — sql_injection")).toBeInTheDocument();
    expect(within(section).getByText("Severity")).toBeInTheDocument();
    expect(within(section).getByText("+75")).toBeInTheDocument();
    expect(within(section).getByText("Validation")).toBeInTheDocument();
    expect(within(section).getAllByText("+10").length).toBeGreaterThanOrEqual(1);
    expect(within(section).getByText("Proof")).toBeInTheDocument();
  });
});

describe("SLA sections", () => {
  it("renders the SLA overview counts", async () => {
    renderPage();
    await loaded();
    const card = screen.getByRole("region", { name: "SLA Overview" });
    expect(within(card).getByText("Active")).toBeInTheDocument();
    expect(within(card).getByText("Breached")).toBeInTheDocument();
    expect(within(card).getByText("Resolved")).toBeInTheDocument();
    expect(within(card).getByText("No SLA")).toBeInTheDocument();
    expect(within(card).getAllByText("2")[0]).toBeInTheDocument();
  });

  it("renders the active SLA table with remaining-time snapshots", async () => {
    renderPage();
    await loaded();
    const table = sectionTable("Active SLA records");
    expect(within(table).getByText("12h 30m remaining")).toBeInTheDocument();
    expect(within(table).getByText("25m remaining")).toBeInTheDocument();
    expect(within(table).getByText("path_traversal")).toBeInTheDocument();
    expect(within(table).getByText("P0")).toBeInTheDocument();
    expect(within(table).getAllByText("Active").length).toBe(2);
    expect(within(table).getAllByText("0").length).toBeGreaterThanOrEqual(2);
  });

  it("renders the SLA breaches section with prominent breached status", async () => {
    renderPage();
    await loaded();
    const section = screen.getByRole("region", { name: "SLA Breaches list" });
    expect(within(section).getByText("SLA BREACHED")).toBeInTheDocument();
    expect(within(section).getByText("command_injection")).toBeInTheDocument();
    expect(within(section).getByText("1")).toBeInTheDocument();
    const link = within(section).getByRole("link", { name: "command_injection" });
    expect(link).toHaveAttribute("href", "/findings/f-cmd-2");
  });

  it("shows empty messages when SLA data is missing", async () => {
    renderPage(
      "/risk",
      stubApi(
        summary({
          sla_overview: { available: false, active: 0, breached: 0, resolved: 0, no_sla: 0 },
          active_slas: [],
          breaches: [],
          escalations: [],
        }),
      ),
    );
    await loaded();
    expect(screen.getByText("No SLA data available")).toBeInTheDocument();
    expect(screen.getByText("No active SLAs")).toBeInTheDocument();
    expect(screen.getByText("No SLA breaches")).toBeInTheDocument();
    expect(screen.getByText("No escalation events")).toBeInTheDocument();
  });
});

describe("escalation timeline", () => {
  it("renders escalation events newest first with levels, reason and time", async () => {
    renderPage();
    await loaded();
    const timeline = screen.getByLabelText("Escalation events");
    const items = within(timeline).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    const first = within(items[0]);
    expect(first.getByText("Level 0")).toBeInTheDocument();
    expect(first.getByText("Level 2")).toBeInTheDocument();
    expect(first.getByText("SLA deadline exceeded for command_injection")).toBeInTheDocument();
    expect(items[1]).toHaveTextContent("Level 1");
    expect(items[1]).toHaveTextContent("SLA deadline exceeded for sql_injection");
    const times = within(timeline).getAllByRole("time");
    expect(times[0]).toHaveAttribute("dateTime", "2026-08-15T09:05:00Z");
  });
});

describe("filters", () => {
  it("filters the tables by priority and persists it to the URL", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    await user.selectOptions(filterSelect("Priority"), "P0");
    const table = sectionTable("Highest Risk Findings");
    expect(within(table).getByText("sql_injection")).toBeInTheDocument();
    expect(within(table).queryByText("command_injection")).not.toBeInTheDocument();
    expect(screen.getByTestId("router-search").textContent).toContain("priority=P0");
  });

  it("filters the highest-risk table by severity", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    await user.selectOptions(filterSelect("Severity"), "high");
    const table = sectionTable("Highest Risk Findings");
    expect(within(table).getByText("command_injection")).toBeInTheDocument();
    expect(within(table).queryByText("sql_injection")).not.toBeInTheDocument();
  });

  it("filters by SLA status across the SLA sections", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    await user.selectOptions(filterSelect("SLA Status"), "breached");
    const findingsTable = sectionTable("Highest Risk Findings");
    expect(within(findingsTable).getByText("command_injection")).toBeInTheDocument();
    expect(within(findingsTable).queryByText("sql_injection")).not.toBeInTheDocument();
    expect(screen.getByText("No active SLAs")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "SLA Breaches list" }).textContent).toContain("command_injection");
  });

  it("filters the escalation timeline by escalation level", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    await user.selectOptions(filterSelect("Escalation Level"), "2");
    const timeline = screen.getByLabelText("Escalation events");
    expect(within(timeline).getAllByRole("listitem")).toHaveLength(1);
    expect(timeline).toHaveTextContent("command_injection");
    expect(timeline).not.toHaveTextContent("sql_injection");
  });

  it("initializes filters from URL query parameters", async () => {
    renderPage("/risk?priority=P1&severity=high");
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    expect(filterSelect("Priority")).toHaveValue("P1");
    expect(filterSelect("Severity")).toHaveValue("high");
    const table = sectionTable("Highest Risk Findings");
    expect(within(table).getByText("command_injection")).toBeInTheDocument();
    expect(within(table).queryByText("sql_injection")).not.toBeInTheDocument();
  });
});

describe("states", () => {
  it("shows the empty state when nothing has been scanned", async () => {
    renderPage(
      "/risk",
      stubApi(
        summary({
          has_findings: false,
          kpis: {
            total_assessments: { available: false, value: 0 },
            critical_p0: { available: false, value: 0 },
            high_p1: { available: false, value: 0 },
            active_slas: { available: false, value: 0 },
            sla_breaches: { available: false, value: 0 },
            escalations: { available: false, value: 0 },
          },
        }),
      ),
    );
    await loaded();
    expect(screen.getByText("No risk data available")).toBeInTheDocument();
    expect(
      screen.getByText(/Risk information will appear after findings have been scanned/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  });

  it("shows structured skeletons while loading", async () => {
    let resolveData: (value: RiskSummary) => void = () => {};
    const pending = new Promise<RiskSummary>((resolve) => {
      resolveData = resolve;
    });
    const fetchMock = vi.fn(async () => {
      return { ok: true, status: 200, json: async () => pending };
    });
    renderPage("/risk", fetchMock);
    await loaded();
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText("sql_injection")).not.toBeInTheDocument();
    resolveData(summary());
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    expect(sectionTable("Highest Risk Findings")).toBeInTheDocument();
  });

  it("shows an alert with retry when loading fails, then recovers", async () => {
    const user = userEvent.setup();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("network down"))
      .mockImplementation(stubApi(summary()));
    renderPage("/risk", fetchMock);
    await loaded();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to load risk data.");
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("accessibility", () => {
  it("provides labeled filters, semantic tables and accessible chart summaries", async () => {
    renderPage();
    await loaded();
    await screen.findByRole("region", { name: "Highest Risk Findings" });
    expect(screen.getByRole("combobox", { name: "Priority" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Severity" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "SLA Status" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Escalation Level" })).toBeInTheDocument();
    const tables = screen.getAllByRole("table");
    for (const table of tables) {
      expect(within(table).getAllByRole("columnheader").length).toBeGreaterThan(0);
    }
    expect(screen.getByRole("img", { name: /Score 61-80/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /P0 — 2 findings/ })).toBeInTheDocument();
    expect(screen.getByText("SLA BREACHED")).toBeInTheDocument();
  });

  it("renders without layout errors at a narrow viewport", async () => {
    window.innerWidth = 640;
    renderPage();
    await loaded();
    const region = await screen.findByRole("region", { name: "Highest Risk Findings" });
    expect(within(region).getByText("sql_injection")).toBeInTheDocument();
    expect(screen.getByText("12h 30m remaining")).toBeInTheDocument();
  });
});
