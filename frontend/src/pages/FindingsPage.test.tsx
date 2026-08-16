import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FindingListItem } from "../api/findings";
import { FindingsPage } from "./FindingsPage";

function finding(overrides: Partial<FindingListItem>): FindingListItem {
  return {
    finding_id: "f-default",
    vulnerability_type: "sql_injection",
    severity: "high",
    scanner_confidence: 0.7,
    priority: "P1",
    risk_score: 75,
    repository: "repo-a",
    file: "users.py",
    source_snippet: "request.args",
    sink_snippet: "cursor.execute",
    source_kind: "request_param",
    sink_kind: "sql_execute",
    verdict: null,
    validation_confidence: null,
    validated_at: null,
    proof_status: null,
    approval_status: null,
    sla: { status: "none", remaining_seconds: null, priority: null },
    ...overrides,
  };
}

function makeFindings(): FindingListItem[] {
  return [
    finding({
      finding_id: "f-sql-1",
      vulnerability_type: "sql_injection",
      severity: "high",
      priority: "P1",
      repository: "repo-a",
      file: "users.py",
      source_snippet: "request.args",
      sink_snippet: "cursor.execute",
      verdict: "true_positive",
      validation_confidence: 0.94,
      proof_status: "verified",
      approval_status: "approved",
      sla: { status: "active", remaining_seconds: 43200, priority: "P1" },
    }),
    finding({
      finding_id: "f-cmd-1",
      vulnerability_type: "command_injection",
      severity: "critical",
      priority: "P0",
      repository: "repo-b",
      file: "cli.py",
      source_snippet: "os.environ",
      sink_snippet: "subprocess.run",
      sla: { status: "breached", remaining_seconds: null, priority: "P0" },
    }),
    finding({
      finding_id: "f-ssrf-1",
      vulnerability_type: "ssrf",
      severity: "medium",
      priority: "P2",
      repository: "repo-a",
      file: "fetch.py",
      source_snippet: "request.args",
      sink_snippet: "requests.get",
      verdict: "uncertain",
      validation_confidence: 0.55,
      proof_status: "blocked",
      sla: { status: "active", remaining_seconds: 7200, priority: "P2" },
    }),
    finding({
      finding_id: "f-sql-2",
      vulnerability_type: "sql_injection",
      severity: "low",
      priority: "P3",
      repository: "repo-c",
      file: "legacy.py",
      source_snippet: "user_input",
      sink_snippet: "db.query",
      verdict: "false_positive",
      validation_confidence: 0.88,
      proof_status: "not_verified",
      approval_status: "rejected",
      sla: { status: "resolved", remaining_seconds: null, priority: "P3" },
    }),
    finding({
      finding_id: "f-cmd-2",
      vulnerability_type: "command_injection",
      severity: "info",
      priority: "P4",
      repository: "repo-b",
      file: "helper.py",
      source_snippet: "data",
      sink_snippet: "os.system",
      approval_status: "pending",
      sla: { status: "none", remaining_seconds: null, priority: null },
    }),
    finding({
      finding_id: "f-sql-3",
      vulnerability_type: "sql_injection",
      severity: "medium",
      priority: "P2",
      repository: "repo-a",
      file: "reports.py",
      source_snippet: "form_value",
      sink_snippet: "db.raw(sql)",
      verdict: "true_positive",
      validation_confidence: 0.82,
      sla: { status: "none", remaining_seconds: null, priority: null },
    }),
    finding({
      finding_id: "f-x",
      vulnerability_type: "ssrf",
      severity: "medium",
      priority: null,
      repository: "repo-c",
      file: "net.py",
      source_snippet: "url_param",
      sink_snippet: "urllib.request.urlopen",
      sla: { status: "none", remaining_seconds: null, priority: null },
    }),
  ];
}

function mockFindings(findings: FindingListItem[]) {
  const fetchMock = vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => findings,
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage(initialEntry = "/findings") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<div>detail-placeholder</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

/* The mobile card list is always in the DOM (hidden by CSS), so content
   assertions are scoped to the table. */
function table() {
  return screen.getByRole("table");
}

function rows() {
  return within(table()).getAllByRole("row").slice(1);
}

async function loaded() {
  await screen.findByText(/^Security findings \(\d+\)$/);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("findings page", () => {
  it("renders the page header", async () => {
    mockFindings(makeFindings());
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "Security Findings", level: 1 }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Detected security issues across analyzed repositories"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("loads findings into the table", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(rows()).toHaveLength(7);
  });

  it("displays finding data", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getByText("users.py")).toBeInTheDocument();
    expect(within(table()).getByText("legacy.py")).toBeInTheDocument();
    expect(within(table()).getByText("reports.py")).toBeInTheDocument();
    expect(within(table()).getAllByText("repo-a")).toHaveLength(3);
  });

  it("displays priority as text", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    for (const priority of ["P0", "P1", "P3", "P4"]) {
      expect(within(table()).getByText(priority)).toBeInTheDocument();
    }
    expect(within(table()).getAllByText("P2")).toHaveLength(2);
  });

  it("displays severity", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
      expect(within(table()).getAllByText(severity).length).toBeGreaterThan(0);
    }
  });

  it("displays the vulnerability type", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getAllByText("SQL Injection")).toHaveLength(3);
    expect(within(table()).getAllByText("Command Injection")).toHaveLength(2);
    expect(within(table()).getAllByText("SSRF")).toHaveLength(2);
  });

  it("displays the repository", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getAllByText("repo-a")).toHaveLength(3);
    expect(within(table()).getAllByText("repo-b")).toHaveLength(2);
    expect(within(table()).getAllByText("repo-c")).toHaveLength(2);
  });

  it("displays source → sink", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getAllByText("request.args")).toHaveLength(2);
    expect(within(table()).getByText("cursor.execute")).toBeInTheDocument();
    expect(within(table()).getByText("os.environ")).toBeInTheDocument();
    expect(within(table()).getByText("subprocess.run")).toBeInTheDocument();
    expect(within(table()).getByText("requests.get")).toBeInTheDocument();
  });

  it("displays validation confidence as a percentage", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getByText("94%")).toBeInTheDocument();
    expect(within(table()).getByText("55%")).toBeInTheDocument();
    expect(within(table()).getByText("88%")).toBeInTheDocument();
    expect(within(table()).getByText("82%")).toBeInTheDocument();
  });

  it("shows an em dash when validation confidence is missing", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const fCmd1Row = rows().find((row) =>
      within(row).queryByText("cli.py"),
    )!;
    expect(within(fCmd1Row).getByText("—")).toBeInTheDocument();
  });

  it("displays SLA status including remaining time", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getAllByText("Active")).toHaveLength(2);
    expect(within(table()).getByText("12h remaining")).toBeInTheDocument();
    expect(within(table()).getByText("2h remaining")).toBeInTheDocument();
    expect(within(table()).getByText("SLA Breached")).toBeInTheDocument();
    expect(within(table()).getByText("Resolved")).toBeInTheDocument();
    expect(within(table()).getAllByText("No SLA")).toHaveLength(3);
  });

  it("displays the derived validation status", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    expect(within(table()).getByText("Approved")).toBeInTheDocument();
    expect(within(table()).getByText("Rejected")).toBeInTheDocument();
    expect(within(table()).getByText("Pending Approval")).toBeInTheDocument();
    expect(within(table()).getByText("Uncertain")).toBeInTheDocument();
    expect(within(table()).getByText("Validated")).toBeInTheDocument();
  });

  it("shows Detected for findings with no lifecycle data", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const fXRawRow = rows().find((row) =>
      within(row).queryByText("net.py"),
    )!;
    expect(within(fXRawRow).getByText("Detected")).toBeInTheDocument();
  });

  it("filters by severity", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by severity" }),
      "HIGH",
    );
    expect(rows()).toHaveLength(1);
    expect(within(table()).getByText("SQL Injection")).toBeInTheDocument();
  });

  it("filters by priority", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by priority" }),
      "P2",
    );
    expect(rows()).toHaveLength(2);
  });

  it("filters by vulnerability type", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by vulnerability" }),
      "ssrf",
    );
    expect(rows()).toHaveLength(2);
  });

  it("filters by validation status", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by validation" }),
      "true_positive",
    );
    expect(rows()).toHaveLength(2);
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by validation" }),
      "not_validated",
    );
    expect(rows()).toHaveLength(3);
  });

  it("filters by proof status", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by proof" }),
      "verified",
    );
    expect(rows()).toHaveLength(1);
  });

  it("filters by SLA status", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by SLA" }),
      "breached",
    );
    expect(rows()).toHaveLength(1);
    expect(within(table()).getByText("SLA Breached")).toBeInTheDocument();
  });

  it("filters by approval status", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by approval" }),
      "approved",
    );
    expect(rows()).toHaveLength(1);
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by approval" }),
      "no_approval",
    );
    expect(rows()).toHaveLength(4);
  });

  it("searches case-insensitively across finding fields", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const search = screen.getByRole("searchbox", { name: "Search findings" });
    await userEvent.type(search, "CURSOR.EXECUTE");
    expect(rows()).toHaveLength(1);
    expect(within(table()).getByText("SQL Injection")).toBeInTheDocument();

    await userEvent.clear(search);
    await userEvent.type(search, "repo-c");
    expect(rows()).toHaveLength(2);
  });

  it("sorts by priority and severity deterministically", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const firstFile = () => within(rows()[0]).getByText(/\.py$/).textContent;

    expect(firstFile()).toBe("cli.py");

    await userEvent.click(screen.getByRole("button", { name: "Priority" }));
    expect(firstFile()).toBe("helper.py");

    await userEvent.click(screen.getByRole("button", { name: "Priority" }));
    expect(firstFile()).toBe("cli.py");

    await userEvent.click(screen.getByRole("button", { name: "Severity" }));
    expect(firstFile()).toBe("cli.py");

    await userEvent.click(screen.getByRole("button", { name: "Severity" }));
    expect(firstFile()).toBe("helper.py");
  });

  it("initializes filters from URL query parameters", async () => {
    mockFindings(makeFindings());
    renderPage("/findings?severity=HIGH&priority=P1&q=request.args");
    await loaded();
    expect(rows()).toHaveLength(1);
    expect(within(table()).getByText("SQL Injection")).toBeInTheDocument();
    expect(
      screen.getByRole("combobox", { name: "Filter by severity" }),
    ).toHaveValue("HIGH");
    expect(
      screen.getByRole("combobox", { name: "Filter by priority" }),
    ).toHaveValue("P1");
    expect(
      screen.getByRole("searchbox", { name: "Search findings" }),
    ).toHaveValue("request.args");
  });

  it("applies filter changes immediately", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by severity" }),
      "LOW",
    );
    expect(rows()).toHaveLength(1);
    expect(within(table()).getByText("legacy.py")).toBeInTheDocument();
  });

  it("navigates to the finding detail route when a row is clicked", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.click(within(table()).getByText("cli.py"));
    expect(await screen.findByText("detail-placeholder")).toBeInTheDocument();
  });

  it("navigates via the vulnerability link", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const links = within(table()).getAllByRole("link", {
      name: "Command Injection",
    });
    expect(links[0]).toHaveAttribute("href", "/findings/f-cmd-1");
    await userEvent.click(links[0]);
    expect(await screen.findByText("detail-placeholder")).toBeInTheDocument();
  });

  it("shows an empty state when there are no findings", async () => {
    mockFindings([]);
    renderPage();
    expect(
      await screen.findByText("No security findings"),
    ).toBeInTheDocument();
    expect(screen.getByText(/appear here after a repository has been scanned/i)).toBeInTheDocument();
  });

  it("explains when filters exclude everything", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by severity" }),
      "INFO",
    );
    await userEvent.selectOptions(
      screen.getByRole("combobox", { name: "Filter by priority" }),
      "P1",
    );
    expect(screen.getByText("No security findings")).toBeInTheDocument();
    expect(screen.getByText(/No findings match the current filters/i)).toBeInTheDocument();
  });

  it("shows skeleton rows while loading", async () => {
    const fetchMock = vi.fn(
      () =>
        new Promise<never>(() => {
          /* never resolves during the test */
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "Security Findings", level: 1 }),
    ).toBeInTheDocument();
    expect(document.querySelectorAll(".f-skeleton").length).toBeGreaterThan(0);
  });

  it("shows an error state and recovers on Retry", async () => {
    let failing = true;
    const fetchMock = vi.fn(async () => {
      if (failing) throw new Error("network down");
      return { ok: true, status: 200, json: async () => makeFindings() };
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByRole("alert", { name: "Findings load error" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Unable to load findings.")).toBeInTheDocument();

    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => {
      expect(screen.getByText(/^Security findings \(\d+\)$/)).toBeInTheDocument();
    });
  });

  it("renders mobile finding cards with key details", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 390,
    });
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const cards = document.querySelectorAll(".f-card:not([aria-hidden])");
    expect(cards.length).toBe(7);
    const firstCard = cards[0];
    expect(within(firstCard as HTMLElement).getByText("P0")).toBeInTheDocument();
    expect(within(firstCard as HTMLElement).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(firstCard as HTMLElement).getByText("Command Injection")).toBeInTheDocument();
    expect(within(firstCard as HTMLElement).getByText("cli.py")).toBeInTheDocument();
    expect(within(firstCard as HTMLElement).getByText("SLA Breached")).toBeInTheDocument();
    expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(
      document.documentElement.clientWidth,
    );
  });

  it("does not fabricate data for missing backend values", async () => {
    mockFindings(makeFindings());
    renderPage();
    await loaded();
    const fXRow = rows().find((row) => within(row).queryByText("net.py"))!;
    expect(within(fXRow).getAllByText("—")).toHaveLength(2);
    expect(within(fXRow).getByText("Detected")).toBeInTheDocument();
    expect(within(fXRow).getByText("No SLA")).toBeInTheDocument();
    expect(screen.queryByText("0%")).not.toBeInTheDocument();
  });
});

describe("findings repository scope", () => {
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

  function scopedFindings(items: FindingListItem[]) {
    return items.filter((item) => item.repository === "repo-a");
  }

  function mockScoped(options: {
    projectStatus?: number;
    findingsStatus?: number;
    findings?: FindingListItem[];
  }) {
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        expect(method).toBe("GET");
        if (url === `/api/findings?project_id=${PROJECT_ID}`) {
          if (options.findingsStatus === 404) {
            return {
              ok: false,
              status: 404,
              json: async () => ({ detail: `project not found: ${PROJECT_ID}` }),
            };
          }
          return {
            ok: true,
            status: 200,
            json: async () => options.findings ?? scopedFindings(makeFindings()),
          };
        }
        if (url === `/api/projects/${PROJECT_ID}`) {
          if (options.projectStatus === 404) {
            return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
          }
          return { ok: true, status: 200, json: async () => PROJECT_DETAIL };
        }
        throw new Error(`unexpected request: ${method} ${url}`);
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("shows the active repository scope and only its findings", async () => {
    mockScoped({});
    renderPage(`/findings?project_id=${PROJECT_ID}`);
    await loaded();
    const scope = screen.getByRole("status");
    expect(scope).toHaveTextContent("Repository:");
    expect(scope).toHaveTextContent("web-app");
    expect(scope.getAttribute("class")).toContain("f-scope");
    expect(
      within(scope).getByRole("link", { name: "Clear filter" }),
    ).toHaveAttribute("href", "/findings");
    expect(rows()).toHaveLength(3);
    expect(within(table()).queryByText("cli.py")).not.toBeInTheDocument();
    expect(within(table()).queryByText("legacy.py")).not.toBeInTheDocument();
    expect(within(table()).getByText("users.py")).toBeInTheDocument();
    expect(within(table()).getByText("fetch.py")).toBeInTheDocument();
    expect(within(table()).getByText("reports.py")).toBeInTheDocument();
  });

  it("shows zero honestly when the repository has no findings", async () => {
    mockScoped({ findings: [] });
    renderPage(`/findings?project_id=${PROJECT_ID}`);
    expect(
      await screen.findByText("0 findings for this repository."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText("No security findings")).not.toBeInTheDocument();
    expect(screen.getByText("Repository:")).toBeInTheDocument();
  });

  it("shows Repository not found for an unknown project without global fallback", async () => {
    const fetchMock = mockScoped({ findingsStatus: 404 });
    renderPage(`/findings?project_id=${PROJECT_ID}`);
    expect(
      await screen.findByRole("alert", { name: "Repository not found" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Repository not found.")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "View all findings" }),
    ).toHaveAttribute("href", "/findings");
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    const urls = fetchMock.mock.calls.map(([input]) => String(input));
    expect(urls.some((url) => url === "/api/findings")).toBe(false);
    expect(urls).toContain(`/api/findings?project_id=${PROJECT_ID}`);
  });

  it("never fetches the unscoped global list while scoped", async () => {
    const fetchMock = mockScoped({});
    renderPage(`/findings?project_id=${PROJECT_ID}`);
    await loaded();
    const urls = fetchMock.mock.calls.map(([input]) => String(input));
    expect(urls).toContain(`/api/findings?project_id=${PROJECT_ID}`);
    expect(urls.some((url) => url === "/api/findings")).toBe(false);
  });

  it("clears the filter back to the global list", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === `/api/findings?project_id=${PROJECT_ID}`) {
        return {
          ok: true,
          status: 200,
          json: async () => scopedFindings(makeFindings()),
        };
      }
      if (url === `/api/projects/${PROJECT_ID}`) {
        return { ok: true, status: 200, json: async () => PROJECT_DETAIL };
      }
      if (url === "/api/findings") {
        return { ok: true, status: 200, json: async () => makeFindings() };
      }
      throw new Error(`unexpected request: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage(`/findings?project_id=${PROJECT_ID}`);
    await loaded();
    expect(rows()).toHaveLength(3);
    await user.click(screen.getByRole("link", { name: "Clear filter" }));
    await waitFor(() => {
      expect(rows()).toHaveLength(7);
    });
    expect(screen.queryByText("Repository:")).not.toBeInTheDocument();
  });
});
