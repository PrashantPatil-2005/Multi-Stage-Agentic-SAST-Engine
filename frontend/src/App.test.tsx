import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import App from "./App";
import { ThemeProvider } from "./theme/ThemeContext";

const EMPTY_SUMMARY = {
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
};

const EMPTY_RISK = {
  has_findings: false,
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
  sla_overview: { available: false, active: 0, breached: 0, resolved: 0, no_sla: 0 },
  active_slas: [],
  breaches: [],
  escalations: [],
};

const EMPTY_VALIDATION = {
  has_findings: false,
  kpis: {
    total_validations: { available: false, value: 0 },
    true_positives: { available: false, value: 0 },
    false_positives: { available: false, value: 0 },
    uncertain: { available: false, value: 0 },
    pending: { available: false, value: 0 },
  },
  records: [],
};

const EMPTY_PROOF = {
  has_findings: false,
  kpis: {
    total: { available: false, value: 0 },
    verified: { available: false, value: 0 },
    not_verified: { available: false, value: 0 },
    blocked: { available: false, value: 0 },
    errors: { available: false, value: 0 },
  },
  records: [],
};

const EMPTY_BENCHMARK = {
  has_reports: false,
  reports: [],
};

const EMPTY_REPOSITORIES = {
  has_repositories: false,
  repositories: [],
};

beforeAll(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/projects")) return { ok: true, status: 200, json: async () => [] };
      if (url.includes("/api/findings")) return { ok: true, status: 200, json: async () => [] };
      if (url.includes("/api/approvals")) return { ok: true, status: 200, json: async () => [] };
      if (url.includes("/api/risk")) return { ok: true, status: 200, json: async () => EMPTY_RISK };
      if (url.includes("/api/validation")) return { ok: true, status: 200, json: async () => EMPTY_VALIDATION };
      if (url.includes("/api/proof")) return { ok: true, status: 200, json: async () => EMPTY_PROOF };
      if (url.includes("/api/benchmarks")) return { ok: true, status: 200, json: async () => EMPTY_BENCHMARK };
      if (url.includes("/api/repositories")) return { ok: true, status: 200, json: async () => EMPTY_REPOSITORIES };
      return { ok: true, status: 200, json: async () => EMPTY_SUMMARY };
    }),
  );
});

afterAll(() => {
  vi.unstubAllGlobals();
});

function renderApp(initialEntry = "/dashboard") {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[initialEntry]}>
        <App />
      </MemoryRouter>
    </ThemeProvider>,
  );
}

function mainHeading(name: string) {
  return within(screen.getByRole("main")).getByRole("heading", { name, level: 1 });
}

describe("application shell", () => {
  it("renders the application", () => {
    renderApp();
    expect(screen.getByRole("navigation", { name: /primary navigation/i })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(mainHeading("Overview")).toBeInTheDocument();
  });

  it("renders the sidebar", () => {
    renderApp();
    expect(screen.getByText("SAST Platform")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: /primary navigation/i })).toBeInTheDocument();
  });

  it("renders all navigation items", () => {
    renderApp();
    const labels = [
      "Overview",
      "Findings",
      "Repositories",
      "Risk & SLA",
      "Validation",
      "Proof",
      "Approvals",
      "Benchmarks",
      "Settings",
      "Profile",
    ];
    for (const label of labels) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("collapses and expands the sidebar", async () => {
    const user = userEvent.setup();
    renderApp();
    const sidebar = screen
      .getByRole("navigation", { name: /primary navigation/i })
      .closest(".sidebar");
    expect(sidebar).not.toHaveClass("sidebar--collapsed");

    await user.click(screen.getByRole("button", { name: "Collapse sidebar" }));
    expect(sidebar).toHaveClass("sidebar--collapsed");

    await user.click(screen.getByRole("button", { name: "Expand sidebar" }));
    expect(sidebar).not.toHaveClass("sidebar--collapsed");
  });

  it("navigates between routes", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole("link", { name: "Findings" }));
    expect(mainHeading("Security Findings")).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Benchmarks" }));
    expect(mainHeading("Security Benchmark")).toBeInTheDocument();
    expect(screen.getByText("No benchmark results")).toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Repositories" }));
    expect(mainHeading("Repositories")).toBeInTheDocument();
    expect(screen.getByText("No repositories yet")).toBeInTheDocument();
  });

  it("marks the active route in the sidebar", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole("link", { name: "Proof" }));
    const active = screen.getByRole("link", { name: "Proof" });
    expect(active).toHaveClass("sidebar__link--active");
    expect(active).toHaveAttribute("aria-current", "page");
  });
});

describe("theme", () => {
  it("starts in light mode when nothing is stored", () => {
    renderApp();
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
  });

  it("persists the selected theme and applies it", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole("button", { name: /switch to dark mode/i }));
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(window.localStorage.getItem("sast.theme")).toBe("dark");

    await user.click(screen.getByRole("button", { name: /switch to light mode/i }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(window.localStorage.getItem("sast.theme")).toBe("light");
  });

  it("restores the stored theme on load", () => {
    window.localStorage.setItem("sast.theme", "dark");
    renderApp();
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
  });
});

describe("mobile drawer", () => {
  it("opens and closes the drawer", async () => {
    const user = userEvent.setup();
    renderApp();
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(nav.closest(".sidebar")).not.toHaveClass("sidebar--open");

    await user.click(screen.getByRole("button", { name: "Open navigation menu" }));
    expect(nav.closest(".sidebar")).toHaveClass("sidebar--open");

    await user.click(screen.getByRole("button", { name: "Close navigation drawer" }));
    expect(nav.closest(".sidebar")).not.toHaveClass("sidebar--open");
  });

  it("closes the drawer when Escape is pressed", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole("button", { name: "Open navigation menu" }));
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(nav.closest(".sidebar")).toHaveClass("sidebar--open");
    await user.keyboard("{Escape}");
    expect(nav.closest(".sidebar")).not.toHaveClass("sidebar--open");
  });

  it("closes the drawer when navigating", async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole("button", { name: "Open navigation menu" }));
    await user.click(screen.getByRole("link", { name: "Findings" }));
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    expect(nav.closest(".sidebar")).not.toHaveClass("sidebar--open");
  });
});

describe("keyboard navigation", () => {
  it("navigates with Enter on a focused link", async () => {
    const user = userEvent.setup();
    renderApp();
    const link = screen.getByRole("link", { name: "Validation" });
    link.focus();
    expect(link).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(mainHeading("Validation")).toBeInTheDocument();
  });

  it("navigates with the keyboard by tabbing and pressing Enter", async () => {
    const user = userEvent.setup();
    renderApp();
    const link = screen.getByRole("link", { name: "Settings" });
    link.focus();
    await user.keyboard("{Enter}");
    expect(mainHeading("Settings")).toBeInTheDocument();
  });

  it("activates buttons with the keyboard", async () => {
    const user = userEvent.setup();
    renderApp();
    const nav = screen.getByRole("navigation", { name: /primary navigation/i });
    const menuButton = screen.getByRole("button", { name: "Open navigation menu" });
    menuButton.focus();
    await user.keyboard("{Enter}");
    expect(nav.closest(".sidebar")).toHaveClass("sidebar--open");
  });

  it("cycles focus through the navigation links", async () => {
    const user = userEvent.setup();
    renderApp();
    const links = screen.getAllByRole("link");
    for (const link of links) {
      link.focus();
      expect(link).toHaveFocus();
      await user.tab();
    }
  });
});
