import { readFileSync } from "node:fs";

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RepositoryList, RepositorySummary } from "../api/repositories";
import type { FindingListItem } from "../api/findings";
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

const NEW_REPO: RepositorySummary = {
  project_id: "cccc0000cccc0000cccc0000cccc0000",
  name: "new-repo",
  source_type: "git",
  language: "python",
  status: "prepared",
  location: "https://github.com/example/new-repo",
  created_at: "2026-08-16T09:00:00Z",
  findings: null,
  risk: null,
  validation: null,
  proof: null,
  sla: null,
};

const PROJECT_OUT = {
  id: NEW_REPO.project_id,
  name: NEW_REPO.name,
  source_type: "git",
  location: NEW_REPO.location,
  language: "python",
  status: "prepared",
  created_at: NEW_REPO.created_at,
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
};

function listOf(...repositories: RepositorySummary[]): RepositoryList {
  return { has_repositories: repositories.length > 0, repositories };
}

function findingItem(
  id: string,
  file: string,
  vulnerabilityType = "sql_injection",
): FindingListItem {
  return {
    finding_id: id,
    vulnerability_type: vulnerabilityType,
    severity: "high",
    scanner_confidence: 0.9,
    priority: null,
    risk_score: null,
    repository: "web-app",
    file,
    source_snippet: "args.get('id')",
    sink_snippet: "cursor.execute(query)",
    source_kind: "request_param",
    sink_kind: "sql_execute",
    verdict: null,
    validation_confidence: null,
    validated_at: null,
    proof_status: null,
    approval_status: null,
    sla: { status: "none", remaining_seconds: null, priority: null },
  };
}

const FINDINGS: FindingListItem[] = [
  findingItem("f-sql-1", "app.py"),
  findingItem("f-sql-2", "app.py"),
  findingItem("f-sql-3", "app.py"),
  findingItem("f-xss-1", "other.py", "xss"),
];

const DEDUP_OUT = {
  total_findings: 3,
  unique_findings: 2,
  duplicate_findings: 1,
  groups: [
    {
      fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      structural_signature:
        "sql_injection|request_param|sql_execute|_n_.args.get ( _lit_ )|_n_.execute ( _n_ )|source->string_construction->sink",
      canonical_finding_id: "f-sql-1",
      member_finding_ids: ["f-sql-1", "f-sql-2"],
      occurrence_count: 2,
      repositories: ["web-app"],
      vulnerability_type: "sql_injection",
      representative_finding: {},
      match_reasons: ["same vulnerability type", "same sink category"],
    },
    {
      fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      structural_signature: "sql_injection|request_param|sql_execute|_lit_|_n_.execute|source->sink",
      canonical_finding_id: "f-sql-3",
      member_finding_ids: ["f-sql-3"],
      occurrence_count: 1,
      repositories: ["web-app"],
      vulnerability_type: "sql_injection",
      representative_finding: {},
      match_reasons: ["same vulnerability type", "same sink category"],
    },
  ],
};

const SCAN_OUT = {
  report_id: "report-2026-0001",
  project_id: REPO_A.project_id,
  created_at: "2026-08-16T10:00:00Z",
  scanned_file_count: 42,
  total_findings: 7,
  by_type: { sql_injection: 3, command_injection: 2, ssrf: 2 },
  finding_ids: ["fid-sqli-0001", "fid-cmdi-0001", "fid-ssrf-0001"],
};

interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

function mockIngestion(options: {
  list: RepositoryList;
  afterCreate?: RepositoryList;
  afterScan?: RepositoryList;
  createResponse?: MockResponse;
  createDelayMs?: number;
  scanResponse?: MockResponse;
  scanDelayMs?: number;
  findingItems?: FindingListItem[];
  projectFiles?: string[];
  dedupResponse?: MockResponse;
  dedupResponses?: MockResponse[];
  dedupDelayMs?: number;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let created = false;
  let scanned = false;
  let dedupCallCount = 0;
  const files = options.projectFiles ?? ["app.py"];
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      if (method === "POST" && url === "/api/projects") {
        if (options.createDelayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.createDelayMs));
        }
        if (options.createResponse) {
          return options.createResponse;
        }
        created = true;
        return { ok: true, status: 201, json: async () => PROJECT_OUT };
      }
      if (
        method === "POST" &&
        url.startsWith("/api/projects/") &&
        url.endsWith("/scan")
      ) {
        if (options.scanDelayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.scanDelayMs));
        }
        if (options.scanResponse) {
          return options.scanResponse;
        }
        scanned = true;
        return { ok: true, status: 200, json: async () => SCAN_OUT };
      }
      if (method === "GET" && url === "/api/findings") {
        return {
          ok: true,
          status: 200,
          json: async () => options.findingItems ?? FINDINGS,
        };
      }
      if (
        method === "GET" &&
        url.startsWith("/api/projects/") &&
        !url.endsWith("/scan")
      ) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            ...PROJECT_OUT,
            files: files.map((path) => ({
              path,
              sha256: `sha-${path}`,
              line_count: 10,
              functions: 1,
              classes: 0,
              imports: 2,
              calls: 3,
              assignments: 4,
              error: null,
            })),
          }),
        };
      }
      if (method === "POST" && url === "/api/deduplicate") {
        if (options.dedupDelayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.dedupDelayMs));
        }
        const responses = options.dedupResponses;
        if (responses && dedupCallCount < responses.length) {
          return responses[dedupCallCount++];
        }
        if (options.dedupResponse) {
          return options.dedupResponse;
        }
        return { ok: true, status: 200, json: async () => DEDUP_OUT };
      }
      if (method === "GET" && url === "/api/repositories") {
        const list =
          created && options.afterCreate
            ? options.afterCreate
            : scanned && options.afterScan
              ? options.afterScan
              : options.list;
        return { ok: true, status: 200, json: async () => list };
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
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
      "Scan",
      "Dedup",
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

describe("repositories onboarding", () => {
  function dialog() {
    return screen.getByRole("dialog", { name: "Add repository" });
  }

  async function openDialog(user: ReturnType<typeof userEvent.setup>) {
    await user.click(screen.getByRole("button", { name: "Add Repository" }));
  }

  async function fillForm(
    user: ReturnType<typeof userEvent.setup>,
    name: string,
    url: string,
  ) {
    await user.type(within(dialog()).getByLabelText("Repository name"), name);
    await user.type(within(dialog()).getByLabelText("Git repository URL"), url);
  }

  it("shows an Add Repository button in the header", async () => {
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    expect(
      screen.getByRole("button", { name: "Add Repository" }),
    ).toBeInTheDocument();
  });

  it("opens the add-repository modal with an accessible name", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await openDialog(user);
    expect(dialog()).toBeInTheDocument();
    expect(dialog()).toHaveAttribute("aria-modal", "true");
  });

  it("exposes labelled repository name and git url inputs", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await openDialog(user);
    expect(
      within(dialog()).getByLabelText("Repository name"),
    ).toBeInTheDocument();
    expect(
      within(dialog()).getByLabelText("Git repository URL"),
    ).toBeInTheDocument();
    expect(
      within(dialog()).getByText(
        "Provide a Git repository URL supported by the server's Git client.",
      ),
    ).toBeInTheDocument();
  });

  it("keeps the submit button disabled until both fields are filled", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await openDialog(user);
    const submit = within(dialog()).getByRole("button", {
      name: "Add Repository",
    });
    expect(submit).toBeDisabled();
    await user.type(within(dialog()).getByLabelText("Repository name"), "demo-app");
    expect(submit).toBeDisabled();
    await user.type(
      within(dialog()).getByLabelText("Git repository URL"),
      "https://github.com/example/demo-app",
    );
    expect(submit).toBeEnabled();
  });

  it("submits the git-first payload with language python", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), onCall });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "demo-app", "https://github.com/example/demo-app");
    await user.click(
      within(dialog()).getByRole("button", { name: "Add Repository" }),
    );
    await screen.findByRole("status");
    const post = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/projects" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(post).toBeDefined();
    const payload = JSON.parse(String(post?.[1]?.body ?? ""));
    expect(payload).toEqual({
      name: "demo-app",
      source_type: "git",
      location: "https://github.com/example/demo-app",
      language: "python",
    });
  });

  it("closes the modal, shows success and refreshes the list", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      afterCreate: listOf(REPO_A, NEW_REPO),
    });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "new-repo", "https://github.com/example/new-repo");
    await user.click(
      within(dialog()).getByRole("button", { name: "Add Repository" }),
    );
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(screen.getByRole("status")).toHaveTextContent(
      "Repository added successfully.",
    );
    expect(
      await within(table()).findByText("new-repo"),
    ).toBeInTheDocument();
  });

  it("surfaces backend 400 details and keeps the modal open", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      createResponse: {
        ok: false,
        status: 400,
        json: async () => ({
          detail:
            "git clone failed: unable to access 'https://github.com/example/demo-app'",
        }),
      },
    });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "demo-app", "https://github.com/example/demo-app");
    await user.click(
      within(dialog()).getByRole("button", { name: "Add Repository" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Unable to add repository: git clone failed: unable to access 'https://github.com/example/demo-app'",
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces backend 422 details", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      createResponse: {
        ok: false,
        status: 422,
        json: async () => ({
          detail: [
            {
              loc: ["body", "name"],
              msg: "Value error, name should have at most 200 characters",
              type: "value_error",
            },
          ],
        }),
      },
    });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "demo-app", "https://github.com/example/demo-app");
    await user.click(
      within(dialog()).getByRole("button", { name: "Add Repository" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Unable to add repository: Value error, name should have at most 200 characters",
    );
  });

  it("surfaces backend 500 details safely without stack traces", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      createResponse: {
        ok: false,
        status: 500,
        json: async () => ({ detail: "prepare failed" }),
      },
    });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "demo-app", "https://github.com/example/demo-app");
    await user.click(
      within(dialog()).getByRole("button", { name: "Add Repository" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to add repository: prepare failed");
    expect(alert.textContent).not.toContain("Traceback");
  });

  it("prevents duplicate submissions while preparing", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      createDelayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    await openDialog(user);
    await fillForm(user, "demo-app", "https://github.com/example/demo-app");
    const submit = within(dialog()).getByRole("button", {
      name: "Add Repository",
    });
    await user.click(submit);
    await waitFor(() => expect(submit).toBeDisabled());
    await user.click(submit);
    const posts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/projects" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(posts).toHaveLength(1);
    await screen.findByRole("status");
  });

  it("closes the modal on Escape", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await openDialog(user);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("moves focus into the modal and restores it to the trigger on close", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    const trigger = screen.getByRole("button", { name: "Add Repository" });
    await user.click(trigger);
    expect(
      within(dialog()).getByLabelText("Repository name"),
    ).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(trigger).toHaveFocus();
  });

  it("marks fields invalid once touched and left empty, without calling the API", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), onCall });
    renderPage();
    await loaded();
    await openDialog(user);
    const nameInput = within(dialog()).getByLabelText("Repository name");
    const urlInput = within(dialog()).getByLabelText("Git repository URL");
    expect(nameInput).not.toHaveAttribute("aria-invalid");
    expect(urlInput).not.toHaveAttribute("aria-invalid");
    await user.type(nameInput, "x");
    await user.clear(nameInput);
    await user.tab();
    expect(nameInput).toHaveAttribute("aria-invalid", "true");
    expect(
      within(dialog()).getByText("Repository name is required."),
    ).toBeInTheDocument();
    await user.type(urlInput, "https://github.com/example/demo-app");
    await user.clear(urlInput);
    await user.tab();
    expect(urlInput).toHaveAttribute("aria-invalid", "true");
    expect(
      within(dialog()).getByText("Git repository URL is required."),
    ).toBeInTheDocument();
    expect(
      onCall.mock.calls.filter(
        ([, init]) => (init?.method ?? "").toUpperCase() === "POST",
      ),
    ).toHaveLength(0);
  });
});

describe("repositories onboarding empty state", () => {
  it("shows an Add Repository CTA in the empty state", async () => {
    mockIngestion({ list: { has_repositories: false, repositories: [] } });
    renderPage();
    await screen.findByText("No repositories yet");
    const empty = screen.getByRole("region", { name: "Repository empty state" });
    expect(
      within(empty).getByRole("button", { name: "Add Repository" }),
    ).toBeInTheDocument();
  });

  it("opens the same onboarding modal from the empty state CTA", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: { has_repositories: false, repositories: [] } });
    renderPage();
    await screen.findByText("No repositories yet");
    const empty = screen.getByRole("region", { name: "Repository empty state" });
    await user.click(within(empty).getByRole("button", { name: "Add Repository" }));
    const opened = screen.getByRole("dialog", { name: "Add repository" });
    expect(opened).toBeInTheDocument();
    expect(
      within(opened).getByLabelText("Repository name"),
    ).toBeInTheDocument();
  });
});

describe("repositories scan", () => {
  function scanButton(name: string) {
    return within(table()).getByRole("button", {
      name: `Scan repository ${name}`,
    });
  }

  async function runScan(
    user: ReturnType<typeof userEvent.setup>,
    name = "web-app",
  ) {
    await user.click(scanButton(name));
    await screen.findByRole("status");
  }

  it("exposes a Scan action for every repository row with the repository name", async () => {
    mockIngestion({ list: listOf(REPO_A, REPO_B) });
    renderPage();
    await loaded();
    expect(scanButton("web-app")).toBeInTheDocument();
    expect(scanButton("legacy-api")).toBeInTheDocument();
  });

  it("calls the scan endpoint with the actual project id and no request body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A, REPO_B), onCall });
    renderPage();
    await loaded();
    await runScan(user);
    const scanCall = onCall.mock.calls.find(
      ([url]) => String(url) === `/api/projects/${REPO_A.project_id}/scan`,
    );
    expect(scanCall).toBeDefined();
    expect(scanCall?.[1]?.body).toBeUndefined();
  });

  it("disables the button, shows Scanning and returns to Scan afterwards", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A), scanDelayMs: 80 });
    renderPage();
    await loaded();
    const button = scanButton("web-app");
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Scanning\u2026");
    await screen.findByRole("status");
    expect(button).toBeEnabled();
    expect(button).toHaveTextContent("Scan");
  });

  it("sends only one scan request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), scanDelayMs: 80, onCall });
    renderPage();
    await loaded();
    const button = scanButton("web-app");
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    await user.click(button);
    const scanPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url).endsWith("/scan") &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(scanPosts).toHaveLength(1);
    await screen.findByRole("status");
  });

  it("keeps unrelated repositories scannable while one is scanning", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A, REPO_B), scanDelayMs: 80 });
    renderPage();
    await loaded();
    await user.click(scanButton("web-app"));
    await waitFor(() => expect(scanButton("web-app")).toBeDisabled());
    expect(scanButton("legacy-api")).toBeEnabled();
    await screen.findByRole("status");
  });

  it("displays the scan result values from the response", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await runScan(user);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("Scan completed");
    expect(banner).toHaveTextContent("web-app");
    expect(banner).toHaveTextContent("Files scanned");
    expect(banner).toHaveTextContent("42");
    expect(banner).toHaveTextContent("Findings");
    expect(banner).toHaveTextContent("7");
    expect(banner).toHaveTextContent("SQL Injection: 3");
    expect(banner).toHaveTextContent("Command Injection: 2");
    expect(banner).toHaveTextContent("SSRF: 2");
  });

  it("renders an honest empty result when total findings is zero", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      scanResponse: {
        ok: true,
        status: 200,
        json: async () => ({
          ...SCAN_OUT,
          scanned_file_count: 5,
          total_findings: 0,
          by_type: {},
          finding_ids: [],
        }),
      },
    });
    renderPage();
    await loaded();
    await runScan(user);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("Scan completed — no findings detected.");
    expect(banner).toHaveTextContent("Files scanned");
    expect(banner).toHaveTextContent("5");
    expect(banner).toHaveTextContent("Findings");
    expect(banner).toHaveTextContent("0");
  });

  it("refreshes the repository data after a successful scan", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    const scannedRepo: RepositorySummary = {
      ...REPO_A,
      findings: {
        total: 7,
        by_priority: { P0: 2, P1: 2, P2: 2, P3: 1, P4: 0 },
        highest_priority: "P0",
      },
    };
    mockIngestion({
      list: listOf(REPO_A),
      afterScan: listOf(scannedRepo),
      onCall,
    });
    renderPage();
    await loaded();
    expect(within(table()).getByText("5")).toBeInTheDocument();
    await runScan(user);
    await waitFor(() => {
      expect(within(table()).getByText("7")).toBeInTheDocument();
    });
    const urls = onCall.mock.calls.map(([url]) => String(url));
    const scanIndex = urls.findIndex((url) => url.endsWith("/scan"));
    expect(urls.indexOf("/api/repositories", scanIndex)).toBeGreaterThan(
      scanIndex,
    );
  });

  it("navigates to the findings route via View Findings", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await runScan(user);
    await user.click(screen.getByRole("link", { name: "View Findings" }));
    expect(await screen.findByText("findings-placeholder")).toBeInTheDocument();
  });

  it("surfaces a 404 error and re-enables the scan button", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      scanResponse: {
        ok: false,
        status: 404,
        json: async () => ({
          detail: `project not found: ${REPO_A.project_id}`,
        }),
      },
    });
    renderPage();
    await loaded();
    const button = scanButton("web-app");
    await user.click(button);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      `Unable to scan repository: project not found: ${REPO_A.project_id}`,
    );
    expect(button).toBeEnabled();
    expect(button).toHaveTextContent("Scan");
  });

  it("surfaces a 500 error safely and allows retry", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      scanResponse: {
        ok: false,
        status: 500,
        json: async () => ({ detail: "code model unavailable" }),
      },
    });
    renderPage();
    await loaded();
    const button = scanButton("web-app");
    await user.click(button);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to scan repository: code model unavailable",
    );
    expect(alert.textContent).not.toContain("Traceback");
    expect(button).toBeEnabled();
  });

  it("triggers no other pipeline stage after a scan", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      afterScan: listOf(REPO_A),
      onCall,
    });
    renderPage();
    await loaded();
    await runScan(user);
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/repositories") ||
        (method === "POST" && path === "/api/projects") ||
        (method === "POST" &&
          path.startsWith("/api/projects/") &&
          path.endsWith("/scan"));
      expect(allowed).toBe(true);
    }
    for (const [url] of onCall.mock.calls) {
      const path = String(url);
      for (const stage of [
        "/deduplicate",
        "/risk",
        "/sla",
        "/validate",
        "/prove",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("exposes the Scan action on mobile repository cards", async () => {
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    const cards = document.querySelector(".repo-cards") as HTMLElement;
    expect(cards).not.toBeNull();
    expect(
      within(cards).getByRole("button", { name: "Scan repository web-app" }),
    ).toBeInTheDocument();
  });

  it("does not render a fake scanned status after scanning", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await runScan(user);
    const row = within(table()).getByText("web-app").closest("tr") as HTMLElement;
    expect(within(row).getByText("Prepared")).toBeInTheDocument();
    expect(screen.queryByText("scanned", { exact: true })).not.toBeInTheDocument();
  });
});

describe("repositories deduplication", () => {
  function dedupButton(name: string) {
    return within(table()).getByRole("button", {
      name: `Deduplicate repository ${name}`,
    });
  }

  async function runDedup(
    user: ReturnType<typeof userEvent.setup>,
    name = "web-app",
  ) {
    await user.click(dedupButton(name));
    await screen.findByRole("status");
  }

  it("exposes a Deduplicate action for every repository row", async () => {
    mockIngestion({ list: listOf(REPO_A, REPO_B) });
    renderPage();
    await loaded();
    expect(dedupButton("web-app")).toBeInTheDocument();
    expect(dedupButton("legacy-api")).toBeInTheDocument();
  });

  it("resolves the repository's finding ids and posts the exact contract body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), onCall });
    renderPage();
    await loaded();
    await runDedup(user);
    const projectGet = onCall.mock.calls.find(
      ([url]) => String(url) === `/api/projects/${REPO_A.project_id}`,
    );
    expect(projectGet).toBeDefined();
    const findingsGet = onCall.mock.calls.find(
      ([url]) => String(url) === "/api/findings",
    );
    expect(findingsGet).toBeDefined();
    const dedupPost = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/deduplicate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(dedupPost).toBeDefined();
    const payload = JSON.parse(String(dedupPost?.[1]?.body ?? ""));
    expect(payload).toEqual({ finding_ids: ["f-sql-1", "f-sql-2", "f-sql-3"] });
  });

  it("shows Deduplicating and disables the button while the request is pending", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A), dedupDelayMs: 80 });
    renderPage();
    await loaded();
    const button = dedupButton("web-app");
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Deduplicating\u2026");
    await screen.findByRole("status");
    expect(button).toBeEnabled();
    expect(button).toHaveTextContent("Deduplicate");
  });

  it("sends only one dedup request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), dedupDelayMs: 80, onCall });
    renderPage();
    await loaded();
    const button = dedupButton("web-app");
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    await user.click(button);
    const dedupPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/deduplicate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(dedupPosts).toHaveLength(1);
    await screen.findByRole("status");
  });

  it("keeps unrelated repositories deduplicable while one is running", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A, REPO_B), dedupDelayMs: 80 });
    renderPage();
    await loaded();
    await user.click(dedupButton("web-app"));
    await waitFor(() => expect(dedupButton("web-app")).toBeDisabled());
    expect(dedupButton("legacy-api")).toBeEnabled();
    await screen.findByRole("status");
  });

  it("displays the real dedup result values without deletion language", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await runDedup(user);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("Deduplication completed");
    expect(banner).toHaveTextContent("web-app");
    expect(banner).toHaveTextContent("3 findings grouped into 2 deduplication groups.");
    expect(banner).toHaveTextContent("Duplicate occurrences: 1");
    expect(banner.textContent).not.toContain("deleted");
    expect(banner.textContent).not.toContain("removed");
  });

  it("renders deduplication groups with canonical and related finding links", async () => {
    const user = userEvent.setup();
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    await runDedup(user);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("sql_injection");
    expect(banner).toHaveTextContent("2 occurrences");
    expect(banner).toHaveTextContent("1 occurrence");
    expect(
      within(banner).getByRole("link", { name: "Canonical: f-sql-1" }),
    ).toHaveAttribute("href", "/findings/f-sql-1");
    expect(
      within(banner).getByRole("link", { name: "f-sql-2" }),
    ).toHaveAttribute("href", "/findings/f-sql-2");
    expect(
      within(banner).getByRole("link", { name: "Canonical: f-sql-3" }),
    ).toHaveAttribute("href", "/findings/f-sql-3");
  });

  it("shows an honest empty state and sends no dedup request when there are no findings", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      findingItems: [findingItem("f-xss-1", "other.py", "xss")],
      onCall,
    });
    renderPage();
    await loaded();
    await runDedup(user);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(
      "No findings available for deduplication.",
    );
    const dedupPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/deduplicate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(dedupPosts).toHaveLength(0);
  });

  it("surfaces a 404 safely and allows retry", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      dedupResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({
            detail: "findings not found: ['f-sql-2']",
          }),
        },
      ],
      onCall,
    });
    renderPage();
    await loaded();
    const button = dedupButton("web-app");
    await user.click(button);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to deduplicate repository: findings not found: ['f-sql-2']",
    );
    expect(alert.textContent).not.toContain("Traceback");
    expect(button).toBeEnabled();
    await user.click(button);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent("Deduplication completed");
    const dedupPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/deduplicate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(dedupPosts).toHaveLength(2);
  });

  it("triggers no other pipeline stage during deduplication", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({ list: listOf(REPO_A), onCall });
    renderPage();
    await loaded();
    await runDedup(user);
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/repositories") ||
        (method === "POST" && path === "/api/projects") ||
        (method === "POST" &&
          path.startsWith("/api/projects/") &&
          path.endsWith("/scan")) ||
        (method === "GET" &&
          path.startsWith("/api/projects/") &&
          !path.endsWith("/scan")) ||
        (method === "GET" && path === "/api/findings") ||
        (method === "POST" && path === "/api/deduplicate");
      expect(allowed).toBe(true);
    }
    for (const [url] of onCall.mock.calls) {
      const path = String(url);
      for (const stage of [
        "/risk",
        "/sla",
        "/validate",
        "/prove",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("exposes the Deduplicate action on mobile repository cards", async () => {
    mockIngestion({ list: listOf(REPO_A) });
    renderPage();
    await loaded();
    const cards = document.querySelector(".repo-cards") as HTMLElement;
    expect(cards).not.toBeNull();
    expect(
      within(cards).getByRole("button", {
        name: "Deduplicate repository web-app",
      }),
    ).toBeInTheDocument();
  });

  it("uses per-repository accessible names and status/alert roles", async () => {
    const user = userEvent.setup();
    mockIngestion({
      list: listOf(REPO_A),
      dedupResponse: {
        ok: false,
        status: 500,
        json: async () => ({ detail: "deduplication failed" }),
      },
    });
    renderPage();
    await loaded();
    expect(
      within(table()).getByRole("button", {
        name: "Deduplicate repository web-app",
      }),
    ).toBeInTheDocument();
    await user.click(dedupButton("web-app"));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to deduplicate repository: deduplication failed",
    );
  });
});

describe("repositories onboarding safety", () => {
  it("only calls the repositories GET and projects POST endpoints during onboarding", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      afterCreate: listOf(REPO_A, NEW_REPO),
      onCall,
    });
    renderPage();
    await loaded();
    await openOnboardingDialog(user);
    await fillOnboardingForm(user);
    await user.click(
      within(screen.getByRole("dialog", { name: "Add repository" })).getByRole(
        "button",
        { name: "Add Repository" },
      ),
    );
    await screen.findByRole("status");
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/repositories") ||
        (method === "POST" && path === "/api/projects");
      expect(allowed).toBe(true);
    }
  });

  it("never requests the scan endpoint during onboarding", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockIngestion({
      list: listOf(REPO_A),
      afterCreate: listOf(REPO_A, NEW_REPO),
      onCall,
    });
    renderPage();
    await loaded();
    await openOnboardingDialog(user);
    await fillOnboardingForm(user);
    await user.click(
      within(screen.getByRole("dialog", { name: "Add repository" })).getByRole(
        "button",
        { name: "Add Repository" },
      ),
    );
    await screen.findByRole("status");
    for (const [url] of onCall.mock.calls) {
      expect(String(url)).not.toContain("/scan");
    }
  });

  it("contains no filesystem, shell or child-process APIs in the onboarding, scan and dedup code", async () => {
    const projectsSource = readFileSync("src/api/projects.ts", "utf-8");
    const dedupSource = readFileSync("src/api/dedup.ts", "utf-8");
    const dedupHookSource = readFileSync(
      "src/hooks/useDeduplication.ts",
      "utf-8",
    );
    const modalSource = readFileSync(
      "src/components/repositories/AddRepositoryModal.tsx",
      "utf-8",
    );
    const tableSource = readFileSync(
      "src/components/repositories/RepositoryTable.tsx",
      "utf-8",
    );
    const pageSource = readFileSync("src/pages/RepositoriesPage.tsx", "utf-8");
    const source =
      projectsSource +
      "\n" +
      dedupSource +
      "\n" +
      dedupHookSource +
      "\n" +
      modalSource +
      "\n" +
      tableSource +
      "\n" +
      pageSource;
    for (const forbidden of [
      "child_process",
      "spawn",
      "exec(",
      "execSync",
      "node:fs",
      'require("fs")',
      "shell",
      "git clone",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });
});

async function openOnboardingDialog(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Add Repository" }));
}

async function fillOnboardingForm(user: ReturnType<typeof userEvent.setup>) {
  const opened = screen.getByRole("dialog", { name: "Add repository" });
  await user.type(within(opened).getByLabelText("Repository name"), "new-repo");
  await user.type(
    within(opened).getByLabelText("Git repository URL"),
    "https://github.com/example/new-repo",
  );
}
