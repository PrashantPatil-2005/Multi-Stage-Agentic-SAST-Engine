import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { DashboardSummary } from "../api/dashboard";
import { DashboardPage } from "./DashboardPage";

function makeSummary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    projects: [
      { id: "p1", name: "project-a" },
      { id: "p2", name: "project-b" },
    ],
    kpis: {
      total_findings: { available: true, value: 12 },
      critical_p0: { available: true, value: 2 },
      sla_breaches: { available: true, value: 1 },
      pending_validation: { available: true, value: 3 },
      pending_approval: { available: true, value: 4 },
    },
    pipeline: [
      {
        stage: "SCAN",
        count: 12,
        count_label: "12 findings",
        description: "Static analysis against bundled security rules",
      },
      {
        stage: "DEDUP",
        count: 8,
        count_label: "8 unique issues",
        description: "Group duplicate findings into unique issues",
      },
      {
        stage: "APPROVAL",
        count: 4,
        count_label: "4 pending approvals",
        description: "Human approval workflow",
      },
    ],
    critical_findings: [
      {
        finding_id: "f1",
        priority: "P0",
        vulnerability_type: "sql_injection",
        repository: "project-a",
        file: "app/db.py",
        status: "verified",
        risk_score: 95,
      },
      {
        finding_id: "f2",
        priority: "P1",
        vulnerability_type: "command_injection",
        repository: "project-a",
        file: "app/utils.py",
        status: "candidate",
        risk_score: 75,
      },
    ],
    sla: {
      available: true,
      active: 5,
      breached: 1,
      highest_priority_breach: "P0",
      escalation_count: 2,
    },
    verification: {
      available: true,
      true_positive: 6,
      false_positive: 1,
      uncertain: 0,
      verified: 3,
      not_verified: 1,
      blocked: 0,
      errors: 0,
    },
    recent_activity: [
      {
        kind: "sla_breached",
        finding_id: "f1",
        message: "SLA breached for P0: due exceeded",
        created_at: "2026-08-14T10:00:00Z",
      },
      {
        kind: "project_created",
        finding_id: null,
        message: "Repository 'project-a' added",
        created_at: "2026-08-13T09:00:00Z",
      },
    ],
    ...overrides,
  };
}

type FetchMock = ReturnType<typeof vi.fn>;

function mockApi({ summary }: { summary: DashboardSummary }) {
  const fetchMock: FetchMock = vi.fn(async (input: RequestInfo | URL) => ({
    ok: true,
    status: 200,
    json: async () =>
      String(input).includes("/api/projects") ? summary.projects : summary,
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage() {
  return render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("dashboard page", () => {
  it("renders the page header and section headings", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "Overview", level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Pipeline" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Critical findings" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "SLA summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Verification" })).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Recent activity" }),
    ).toBeInTheDocument();
  });

  it("renders KPI cards with real backend values", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    expect(await screen.findByText("12")).toBeInTheDocument();
    const kpiArea = screen.getByLabelText("Total Findings");
    expect(within(kpiArea).getByText("Total Findings")).toBeInTheDocument();
    expect(screen.getByLabelText("Critical / P0")).toBeInTheDocument();
    expect(screen.getByLabelText("SLA Breaches")).toBeInTheDocument();
    expect(screen.getByLabelText("Pending Validation")).toBeInTheDocument();
    expect(screen.getByLabelText("Pending Approval")).toBeInTheDocument();
  });

  it("renders the pipeline stages with counts", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Pipeline" });
    expect(screen.getByText("SCAN")).toBeInTheDocument();
    expect(screen.getByText("12 findings")).toBeInTheDocument();
    expect(screen.getByText("DEDUP")).toBeInTheDocument();
    expect(screen.getByText("8 unique issues")).toBeInTheDocument();
    expect(screen.getByText("APPROVAL")).toBeInTheDocument();
    expect(screen.getByText("4 pending approvals")).toBeInTheDocument();
  });

  it("renders critical findings with priorities and statuses", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Critical findings" });
    expect(screen.getByText("sql_injection")).toBeInTheDocument();
    expect(screen.getByText("command_injection")).toBeInTheDocument();
    expect(screen.getByText("app/db.py")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("candidate")).toBeInTheDocument();
  });

  it("links critical findings to their finding page", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Critical findings" });
    const link = screen.getByRole("link", { name: /sql_injection/ });
    expect(link).toHaveAttribute("href", "/findings/f1");
  });

  it("renders the SLA summary values", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "SLA summary" });
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Breached")).toBeInTheDocument();
    expect(screen.getByText("Highest-priority breach")).toBeInTheDocument();
    expect(screen.getByText("Escalations")).toBeInTheDocument();
    const slaCard = screen.getByRole("heading", { name: "SLA summary" }).closest("section")!;
    expect(within(slaCard).getByText("P0")).toBeInTheDocument();
    expect(within(slaCard).getByText("5")).toBeInTheDocument();
    expect(within(slaCard).getByText("2")).toBeInTheDocument();
  });

  it("renders the validation and proof verification counts", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Verification" });
    expect(screen.getByText("True positives")).toBeInTheDocument();
    expect(screen.getByText("False positives")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Not verified")).toBeInTheDocument();
    expect(screen.getByText("Errors")).toBeInTheDocument();
  });

  it("renders recent activity items from real events", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Recent activity" });
    expect(
      screen.getByText("SLA breached for P0: due exceeded"),
    ).toBeInTheDocument();
    expect(screen.getByText("Repository 'project-a' added")).toBeInTheDocument();
    expect(screen.getByText("SLA breach")).toBeInTheDocument();
    expect(screen.getByText("Project")).toBeInTheDocument();
  });

  it("offers a repository selector with real projects", async () => {
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Overview", level: 1 });
    const select = screen.getByRole("combobox", { name: "Repository" });
    expect(within(select).getByRole("option", { name: "All repositories" })).toBeInTheDocument();
    expect(within(select).getByRole("option", { name: "project-a" })).toBeInTheDocument();
    expect(within(select).getByRole("option", { name: "project-b" })).toBeInTheDocument();
  });

  it("shows a no-repositories hint instead of a selector", async () => {
    const summary = makeSummary();
    summary.projects = [];
    mockApi({ summary });
    renderPage();
    await screen.findByRole("heading", { name: "Overview", level: 1 });
    expect(screen.getByText("No repositories")).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Repository" })).not.toBeInTheDocument();
  });

  it("shows an intentional empty state when the backend has no data", async () => {
    const summary = makeSummary({
      projects: [],
      kpis: {
        total_findings: { available: false, value: 0 },
        critical_p0: { available: false, value: 0 },
        sla_breaches: { available: false, value: 0 },
        pending_validation: { available: false, value: 0 },
        pending_approval: { available: false, value: 0 },
      },
      pipeline: [],
      critical_findings: [],
      sla: {
        available: false,
        active: 0,
        breached: 0,
        highest_priority_breach: null,
        escalation_count: 0,
      },
      verification: {
        available: false,
        true_positive: 0,
        false_positive: 0,
        uncertain: 0,
        verified: 0,
        not_verified: 0,
        blocked: 0,
        errors: 0,
      },
      recent_activity: [],
    });
    mockApi({ summary });
    renderPage();
    expect(
      await screen.findByText(/No repositories yet/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Go to Repositories" }),
    ).toHaveAttribute("href", "/repositories");
    expect(screen.getByText("No findings assessed yet.")).toBeInTheDocument();
    expect(screen.getByText("No SLA records yet.")).toBeInTheDocument();
    expect(screen.getByText("No validation or proof results yet.")).toBeInTheDocument();
    expect(screen.getByText("No recent activity.")).toBeInTheDocument();
  });

  it("never fabricates numbers: unavailable KPIs render as dashes", async () => {
    const summary = makeSummary();
    summary.projects = [];
    summary.kpis = {
      total_findings: { available: true, value: 12 },
      critical_p0: { available: false, value: 0 },
      sla_breaches: { available: false, value: 0 },
      pending_validation: { available: false, value: 0 },
      pending_approval: { available: false, value: 0 },
    };
    mockApi({ summary });
    renderPage();
    await screen.findByText("12");
    const unavailable = [
      "Critical / P0",
      "SLA Breaches",
      "Pending Validation",
      "Pending Approval",
    ];
    for (const label of unavailable) {
      const card = screen.getByLabelText(label);
      expect(within(card).getByText("—")).toBeInTheDocument();
      expect(within(card).getByText("No data available")).toBeInTheDocument();
    }
  });

  it("shows skeleton placeholders while loading", async () => {
    const fetchMock: FetchMock = vi.fn(
      () =>
        new Promise<never>(() => {
          /* never resolves during the test */
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(screen.getByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
    expect(document.querySelectorAll(".dash-skeleton").length).toBeGreaterThan(0);
  });

  it("shows an error state and recovers when Retry succeeds", async () => {
    let failing = true;
    const fetchMock: FetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (failing) {
        throw new Error("network down");
      }
      return {
        ok: true,
        status: 200,
        json: async () =>
          String(input).includes("/api/projects")
            ? makeSummary().projects
            : makeSummary(),
      };
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByRole("alert", { name: "Security data error" }),
    ).toBeInTheDocument();

    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Pipeline" })).toBeInTheDocument();
    });
  });

  it("renders without horizontal overflow on a mobile viewport", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 390,
    });
    mockApi({ summary: makeSummary() });
    renderPage();
    await screen.findByRole("heading", { name: "Recent activity" });
    expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(
      document.documentElement.clientWidth,
    );
  });
});
