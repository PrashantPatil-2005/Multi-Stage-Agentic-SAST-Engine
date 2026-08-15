import { readFileSync } from "node:fs";

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RepositoryList, RepositorySummary } from "../api/repositories";
import { RepositoriesPage } from "./RepositoriesPage";

const REPO_A: RepositorySummary = {
  project_id: "aaaa0000aaaa0000aaaa0000aaaa0000",
  name: "web-app",
  source_type: "git",
  language: "python",
  status: "prepared",
  location: "https://github.com/example/web-app",
  created_at: "2026-08-15T09:00:00Z",
  findings: {
    total: 5,
    by_priority: { P0: 1, P1: 2, P2: 1, P3: 1, P4: 0 },
    highest_priority: "P0",
  },
  risk: {
    available: true,
    highest_risk_score: 95,
    highest_priority: "P0",
    top_finding_id: "fid-aaaa-1",
  },
  validation: {
    available: true,
    true_positive: 2,
    false_positive: 1,
    uncertain: 2,
  },
  proof: {
    available: true,
    verified: 1,
    not_verified: 0,
    blocked: 0,
    error: 0,
  },
  sla: { available: true, active: 1, breached: 1, resolved: 0 },
};

const REPO_B: RepositorySummary = {
  project_id: "bbbb0000bbbb0000bbbb0000bbbb0000",
  name: "legacy-api",
  source_type: "directory",
  language: "python",
  status: "prepared",
  location: "/srv/legacy-api",
  created_at: "2026-08-10T09:00:00Z",
  findings: null,
  risk: null,
  validation: null,
  proof: null,
  sla: null,
};

function listOf(...repositories: RepositorySummary[]): RepositoryList {
  return { has_repositories: repositories.length > 0, repositories };
}

function mockRepositories(list: RepositoryList, onCall?: (url: string) => void) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    onCall?.(url);
    if (url === "/api/repositories") {
      return { ok: true, status: 200, json: async () => list };
    }
    throw new Error(`unexpected request: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage(initialEntry = "/repositories") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <LocationSpy />
      <Routes>
        <Route path="/repositories" element={<RepositoriesPage />} />
        <Route path="/findings" element={<div>findings-placeholder</div>} />
        <Route
          path="/findings/:id"
          element={<div>finding-detail-placeholder</div>}
        />
      </Routes>
    </MemoryRouter>,
  );
}

function LocationSpy() {
  const location = useLocation();
  return <div data-testid="location-search">{location.search}</div>;
}

/* The mobile card list is always in the DOM (hidden by CSS), so content
   assertions are scoped to the table. */
function table() {
  return screen.getByRole("table");
}

async function loaded() {
  await screen.findByRole("region", { name: "Repository inventory" });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("repositories page", () => {
  it("renders the page header with refresh", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "Repositories", level: 1 }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Projects and repositories monitored by the security scanner"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("loads repositories into the table", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(2);
  });

  it("renders repository names", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    expect(within(table()).getByText("web-app")).toBeInTheDocument();
    expect(within(table()).getByText("legacy-api")).toBeInTheDocument();
  });

  it("renders the project id in shortened form", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    const cell = within(table()).getByText("aaaa0000");
    expect(cell).toHaveAttribute(
      "title",
      "aaaa0000aaaa0000aaaa0000aaaa0000",
    );
  });

  it("renders the finding count and priority breakdown", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    expect(within(table()).getByText("5")).toBeInTheDocument();
    expect(within(table()).getByText("P0 1")).toBeInTheDocument();
    expect(within(table()).getByText("P1 2")).toBeInTheDocument();
  });

  it("renders the highest priority when available", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    const row = within(table())
      .getAllByRole("row")
      .find((r) => within(r).queryByText("web-app"));
    expect(row).toBeDefined();
    expect(within(row as HTMLElement).getAllByRole("cell")[4]).toHaveTextContent(
      "P0",
    );
  });

  it("renders the risk summary when available", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(within(table()).getByText("Score 95")).toBeInTheDocument();
  });

  it("renders the validation summary when available", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(within(table()).getByText("True positive 2")).toBeInTheDocument();
    expect(within(table()).getByText("False positive 1")).toBeInTheDocument();
    expect(within(table()).getByText("Uncertain 2")).toBeInTheDocument();
  });

  it("renders the proof summary when available", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(within(table()).getByText("Verified 1")).toBeInTheDocument();
    expect(within(table()).getByText("Not verified 0")).toBeInTheDocument();
    expect(within(table()).getByText("Blocked 0")).toBeInTheDocument();
    expect(within(table()).getByText("Error 0")).toBeInTheDocument();
  });

  it("renders the SLA summary when available", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(within(table()).getByText("Active 1")).toBeInTheDocument();
    expect(within(table()).getByText("Breached 1")).toBeInTheDocument();
    expect(within(table()).getByText("Resolved 0")).toBeInTheDocument();
  });

  it("renders the created date", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(within(table()).getByText("Aug 15, 2026")).toBeInTheDocument();
  });

  it("shows dashes when optional data is missing", async () => {
    mockRepositories(listOf(REPO_B));
    renderPage();
    await loaded();
    expect(within(table()).getAllByText("\u2014").length).toBeGreaterThanOrEqual(5);
  });

  it("renders the summary strip with aggregate counts", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    expect(within(screen.getByRole("region", { name: "Repositories" })).getByText("2")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Total Findings" })).getByText("5")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "With Risk Assessment" })).getByText("1")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "SLA Breaches" })).getByText("1")).toBeInTheDocument();
  });
});

describe("repositories search", () => {
  it("searches across name, project id, location and source type", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    const search = screen.getByRole("searchbox", { name: "Search repositories" });

    await user.type(search, "WEB");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("web-app")).toBeInTheDocument();
    expect(within(table()).queryByText("legacy-api")).not.toBeInTheDocument();

    await user.clear(search);
    await user.type(search, "bbbb0000");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("legacy-api")).toBeInTheDocument();

    await user.clear(search);
    await user.type(search, "srv/legacy");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("legacy-api")).toBeInTheDocument();
  });

  it("shows a message when no repositories match the filters", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    await user.type(
      screen.getByRole("searchbox", { name: "Search repositories" }),
      "zzz-no-match",
    );
    expect(
      await screen.findByText("No repositories match the current filters."),
    ).toBeInTheDocument();
  });
});

describe("repositories filters", () => {
  it("filters by highest priority", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    await user.selectOptions(screen.getByRole("combobox", { name: "Priority" }), "P0");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("web-app")).toBeInTheDocument();
  });

  it("filters by SLA status", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    await user.selectOptions(screen.getByRole("combobox", { name: "SLA" }), "breached");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("web-app")).toBeInTheDocument();

    await user.selectOptions(screen.getByRole("combobox", { name: "SLA" }), "active");
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
  });

  it("initializes filters from URL parameters", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage("/repositories?priority=P0");
    await loaded();
    await waitFor(() => {
      expect(within(table()).getAllByRole("row").slice(1)).toHaveLength(1);
    });
    expect(within(table()).getByText("web-app")).toBeInTheDocument();
  });

  it("persists filter changes in URL parameters", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    await user.selectOptions(screen.getByRole("combobox", { name: "Priority" }), "P0");
    await waitFor(() => {
      expect(
        screen.getByTestId("location-search").textContent,
      ).toContain("priority=P0");
    });
  });
});

describe("repositories navigation", () => {
  it("links a repository to the findings page", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    const link = within(table()).getByRole("link", { name: "web-app" });
    expect(link).toHaveAttribute("href", "/findings");
    await user.click(link);
    expect(await screen.findByText("findings-placeholder")).toBeInTheDocument();
  });

  it("links the highest priority finding with its real id", async () => {
    const user = userEvent.setup();
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    const link = within(table()).getByRole("link", {
      name: "Open highest priority finding fid-aaaa-1",
    });
    expect(link).toHaveAttribute("href", "/findings/fid-aaaa-1");
    await user.click(link);
    expect(
      await screen.findByText("finding-detail-placeholder"),
    ).toBeInTheDocument();
  });
});

describe("repositories states", () => {
  it("shows the empty state", async () => {
    mockRepositories({ has_repositories: false, repositories: [] });
    renderPage();
    expect(await screen.findByText("No repositories yet")).toBeInTheDocument();
    expect(
      screen.getByText("Repositories will appear after projects are registered."),
    ).toBeInTheDocument();
  });

  it("shows structured skeletons while loading", async () => {
    let resolveList: (value: RepositoryList) => void = () => {};
    const pending = new Promise<RepositoryList>((resolve) => {
      resolveList = resolve;
    });
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => pending,
    }));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByRole("heading", { name: "Repositories", level: 1 });
    expect(document.querySelector('[aria-busy="true"]')).not.toBeNull();
    expect(screen.queryByText("web-app")).not.toBeInTheDocument();
    resolveList(listOf(REPO_A));
    await loaded();
    expect(within(table()).getByText("web-app")).toBeInTheDocument();
  });

  it("shows an alert with retry when loading fails, then recovers", async () => {
    const user = userEvent.setup();
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("network down"))
      .mockImplementation(
        mockRepositories(listOf(REPO_A)),
      );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to load repositories.");
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await loaded();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("repositories safety", () => {
  it("only ever calls the read-only repositories endpoint", async () => {
    const onCall = vi.fn();
    mockRepositories(listOf(REPO_A, REPO_B), onCall);
    renderPage();
    await loaded();
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url] of onCall.mock.calls) {
      expect(url).toBe("/api/repositories");
    }
  });

  it("never fabricates repository data", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    const rows = within(table()).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      const text = row.textContent ?? "";
      expect(text === "" || text.includes("web-app") || text.includes("legacy-api")).toBe(true);
    }
  });

  it("never fabricates finding ids", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    const links = within(table()).queryAllByRole("link");
    for (const link of links) {
      const href = link.getAttribute("href") ?? "";
      if (href.startsWith("/findings/")) {
        expect(href).toBe("/findings/fid-aaaa-1");
      }
    }
  });
});

describe("repositories responsive and accessibility", () => {
  it("uses a table on desktop, hidden columns on tablet and cards on mobile", async () => {
    mockRepositories(listOf(REPO_A));
    renderPage();
    await loaded();
    expect(document.querySelector(".repo-table")).not.toBeNull();
    expect(document.querySelector(".repo-cards")).not.toBeNull();
    const css = readFileSync(
      "src/components/repositories/repositories.css",
      "utf-8",
    );
    expect(css).toContain("@media (max-width: 1100px)");
    expect(css).toContain("@media (max-width: 768px)");
    expect(css).toContain(".repo-table-wrap {");
    expect(css).toContain("display: none");
    expect(css).toContain(".repo-cards {");
  });

  it("exposes a semantic table, labeled controls and links", async () => {
    mockRepositories(listOf(REPO_A, REPO_B));
    renderPage();
    await loaded();
    const headers = within(table())
      .getAllByRole("columnheader")
      .map((header) => header.textContent);
    expect(headers).toEqual([
      "Repository",
      "Project ID",
      "Status",
      "Findings",
      "Highest Priority",
      "Risk",
      "Validation",
      "Proof",
      "SLA",
      "Created",
    ]);
    expect(
      screen.getByRole("searchbox", { name: "Search repositories" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Priority" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "SLA" })).toBeInTheDocument();
    const nameLink = within(table()).getByRole("link", { name: "web-app" });
    nameLink.focus();
    expect(nameLink).toHaveFocus();
    expect(
      within(table()).getByRole("link", {
        name: "Open highest priority finding fid-aaaa-1",
      }),
    ).toHaveAttribute("href", "/findings/fid-aaaa-1");
  });
});
