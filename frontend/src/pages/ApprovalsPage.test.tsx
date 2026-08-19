import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useParams } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApprovalListItem, ApprovalRequest } from "../api/approvals";
import type { FindingDetail } from "../api/findingDetail";
import { ApprovalsPage } from "./ApprovalsPage";

vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "u1",
      username: "manager",
      display_name: "Security Manager",
      role: "manager",
      is_active: true,
    },
    loading: false,
    isAuthenticated: true,
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

const FID1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const FID2 = "cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

const NOW = "2026-08-15T11:05:00Z";

/* ------------------------------------------------------------------ */
/* fixture builders                                                    */
/* ------------------------------------------------------------------ */

function item(overrides: Partial<ApprovalListItem> = {}): ApprovalListItem {
  return {
    approval_id: "ap-1",
    finding_id: FID1,
    status: "pending",
    action: "remediation",
    version: 1,
    requested_by: "system",
    requested_at: NOW,
    reviewed_by: null,
    reviewed_at: null,
    reason: null,
    vulnerability_type: "sql_injection",
    severity: "high",
    priority: "P1",
    risk_score: 75,
    repository: "repo-a",
    file: "users.py",
    ...overrides,
  };
}

function requestOf(itemData: ApprovalListItem): ApprovalRequest {
  return {
    id: itemData.approval_id,
    finding_id: itemData.finding_id,
    status: itemData.status,
    requested_at: itemData.requested_at,
    requested_by: itemData.requested_by,
    reviewed_at: itemData.reviewed_at,
    reviewed_by: itemData.reviewed_by,
    reason: itemData.reason,
    action: itemData.action,
    version: itemData.version,
  };
}

function findingOf(itemData: ApprovalListItem): FindingDetail {
  return {
    finding_id: itemData.finding_id,
    vulnerability_type: itemData.vulnerability_type ?? "sql_injection",
    severity: itemData.severity ?? "high",
    scanner_confidence: 0.7,
    status: "candidate",
    repository: itemData.repository,
    source: {
      file: itemData.file ?? "users.py",
      line: 18,
      snippet: 'request.args.get("id")',
      kind: "request_param",
    },
    sink: {
      file: itemData.file ?? "users.py",
      line: 27,
      snippet: "cursor.execute(query)",
      kind: "sql_execute",
    },
    taint_path: [
      {
        file: itemData.file ?? "users.py",
        line: 18,
        snippet: 'request.args.get("id")',
        step_type: "source",
      },
      {
        file: itemData.file ?? "users.py",
        line: 27,
        snippet: "cursor.execute(query)",
        step_type: "sink",
      },
    ],
    risk: {
      finding_id: itemData.finding_id,
      vulnerability_type: itemData.vulnerability_type ?? "sql_injection",
      severity: itemData.severity ?? "high",
      risk_score: itemData.risk_score ?? 75,
      priority: itemData.priority ?? "P1",
      factors: [
        {
          name: "severity",
          value: "high",
          points: 75,
          description: "base severity weight (HIGH = 75)",
        },
      ],
      assessed_at: NOW,
      related_finding_ids: [],
    },
    sla: {
      status: "active",
      priority: itemData.priority ?? "P1",
      started_at: "2026-08-15T09:00:00Z",
      due_at: "2026-08-15T21:00:00Z",
      breached_at: null,
      resolved_at: null,
      escalation_level: 0,
      remaining_seconds: 43200,
    },
    validation: {
      finding_id: itemData.finding_id,
      verdict: "true_positive",
      confidence: 0.94,
      reasoning: "Value flows from request.args into an SQL query without sanitization.",
      evidence_used: ["source_snippet", "sink_snippet"],
      missing_evidence: [],
      recommended_next_step: "prove",
      model: "fake-model",
      validated_at: "2026-08-15T10:30:00Z",
    },
    proof: {
      status: "verified",
      confidence: 0.99,
      summary: "Sandboxed execution confirmed the SQL statement reaches the sink.",
      created_at: "2026-08-15T11:00:00Z",
      duration_ms: 1234,
      error: null,
      sandbox_policy: {
        network_enabled: false,
        allow_loopback: false,
        allowed_paths: [],
        timeout_seconds: 10,
        max_output_bytes: 16384,
        max_processes: 1,
        temporary_directory: "/tmp/sandbox",
      },
    },
    approval: requestOf(itemData),
    dedup: null,
  };
}

interface ApprovalHistoryEventFixture {
  id: string;
  approval_id: string;
  finding_id: string;
  previous_status: string | null;
  new_status: string;
  actor: string;
  reason: string | null;
  created_at: string;
}

function eventOf(
  overrides: Partial<ApprovalHistoryEventFixture> = {},
): ApprovalHistoryEventFixture {
  return {
    id: "ev-1",
    approval_id: "ap-1",
    finding_id: FID1,
    previous_status: null,
    new_status: "pending",
    actor: "system",
    reason: null,
    created_at: NOW,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */
/* scenario + fetch stub                                               */
/* ------------------------------------------------------------------ */

interface Scenario {
  items: ApprovalListItem[];
  requests: Record<string, ApprovalRequest>;
  histories: Record<string, ApprovalHistoryEventFixture[]>;
}

function scenario(items: ApprovalListItem[]): Scenario {
  const requests: Scenario["requests"] = {};
  const histories: Scenario["histories"] = {};
  for (const entry of items) {
    requests[entry.approval_id] = requestOf(entry);
    histories[entry.approval_id] = [
      eventOf({
        id: `ev-${entry.approval_id}-1`,
        approval_id: entry.approval_id,
        finding_id: entry.finding_id,
        previous_status: null,
        new_status: "pending",
        actor: entry.requested_by,
        created_at: entry.requested_at,
      }),
    ];
  }
  return { items, requests, histories };
}

interface RouteSpec {
  method: "GET" | "POST";
  pattern: RegExp;
  respond: (
    match: RegExpMatchArray,
    body: unknown,
  ) => { status: number; json: unknown } | Promise<{ status: number; json: unknown }>;
}

type DecisionHandler = (
  kind: string,
  body: unknown,
  scenarioData: Scenario,
  approvalId: string,
) => { status: number; json: unknown } | Promise<{ status: number; json: unknown }>;

function stubApi(
  scenarioData: Scenario,
  decision?: DecisionHandler,
): ReturnType<typeof vi.fn> {
  const routes: RouteSpec[] = [
    {
      method: "GET",
      pattern: /^\/api\/approvals$/,
      respond: () => ({ status: 200, json: scenarioData.items }),
    },
    {
      method: "GET",
      pattern: /^\/api\/findings\/([^/]+)\/approval$/,
      respond: ([, findingId]) => {
        const request = Object.values(scenarioData.requests).find(
          (r) => r.finding_id === findingId,
        );
        return request
          ? { status: 200, json: request }
          : { status: 404, json: { detail: "no approval request for finding" } };
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/findings\/([^/]+)$/,
      respond: ([, findingId]) => {
        const entry = scenarioData.items.find((i) => i.finding_id === findingId);
        return entry
          ? { status: 200, json: findingOf(entry) }
          : { status: 404, json: { detail: "finding not found" } };
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/approvals\/([^/]+)\/history$/,
      respond: ([, approvalId]) => ({
        status: 200,
        json: scenarioData.histories[approvalId] ?? [],
      }),
    },
    {
      method: "POST",
      pattern: /^\/api\/approvals\/([^/]+)\/(approve|reject|request-changes|resubmit)$/,
      respond: ([, approvalId, kind], body) =>
        decision
          ? decision(kind, body, scenarioData, approvalId)
          : defaultDecision(kind, body, scenarioData, approvalId),
    },
  ];

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? "GET").toUpperCase();
    const route = routes.find((r) => r.method === method && r.pattern.test(url));
    if (!route) {
      return {
        ok: false,
        status: 404,
        json: async () => ({ detail: `no mock: ${method} ${url}` }),
      };
    }
    let body: unknown;
    const bodyText = init?.body;
    if (typeof bodyText === "string") {
      try {
        body = JSON.parse(bodyText);
      } catch {
        body = bodyText;
      }
    }
    const match = url.match(route.pattern) ?? ([] as unknown as RegExpMatchArray);
    const result = await route.respond(match, body);
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      json: async () => result.json,
    };
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function defaultDecision(
  kind: string,
  body: unknown,
  scenarioData: Scenario,
  approvalId: string,
): { status: number; json: unknown } {
  const request = scenarioData.requests[approvalId];
  if (!request) {
    return { status: 404, json: { detail: `approval not found: ${approvalId}` } };
  }
  const decision = (body ?? {}) as { reviewed_by?: string; reason?: string };
  const previous = request.status;
  const next =
    kind === "approve"
      ? "approved"
      : kind === "reject"
        ? "rejected"
        : kind === "request-changes"
          ? "changes_requested"
          : "pending";
  if (kind === "resubmit") {
    request.version += 1;
    request.reviewed_by = null;
    request.reviewed_at = null;
    request.reason = decision.reason ?? null;
  } else {
    request.reviewed_by = decision.reviewed_by ?? "security-analyst";
    request.reviewed_at = NOW;
    request.reason = decision.reason ?? null;
  }
  request.status = next;
  scenarioData.histories[approvalId].push(
    eventOf({
      id: `ev-${approvalId}-${scenarioData.histories[approvalId].length + 1}`,
      approval_id: approvalId,
      finding_id: request.finding_id,
      previous_status: previous,
      new_status: next,
      actor: request.reviewed_by ?? "security-analyst",
      reason: request.reason,
      created_at: NOW,
    }),
  );
  const entry = scenarioData.items.find((i) => i.approval_id === approvalId);
  if (entry) {
    entry.status = request.status;
    entry.reviewed_by = request.reviewed_by;
    entry.reviewed_at = request.reviewed_at;
    entry.reason = request.reason;
    entry.version = request.version;
  }
  return { status: 200, json: request };
}

/* ------------------------------------------------------------------ */
/* render helpers                                                      */
/* ------------------------------------------------------------------ */

function FindingStub() {
  const { id } = useParams();
  return <div>finding-detail-stub:{id}</div>;
}

function renderPage(initialEntry = "/approvals") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/approvals" element={<ApprovalsPage />} />
        <Route path="/findings/:id" element={<FindingStub />} />
      </Routes>
    </MemoryRouter>,
  );
}

function reviewPanel() {
  return screen.getByText("Approval Review").closest("section") as HTMLElement;
}

/** Waits until the review panel has loaded the request + finding. */
async function reviewPanelLoaded() {
  const panel = reviewPanel();
  await within(panel).findByText("Approval Request");
  return panel;
}

/** Waits until the review panel card is rendered (any state). */
async function reviewPanelAppeared() {
  const title = await screen.findByText("Approval Review");
  return title.closest("section") as HTMLElement;
}

function tab(name: RegExp | string) {
  return screen.getByRole("tab", { name });
}

function dialog(name: string) {
  return screen.getByRole("dialog", { name });
}

async function loaded() {
  await screen.findByRole("heading", { level: 1 });
}

function postsOf(fetchMock: ReturnType<typeof vi.fn>): [string, RequestInit][] {
  return fetchMock.mock.calls
    .filter(([, init]) => init?.method === "POST")
    .map(([url, init]) => [String(url), init as RequestInit]);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ------------------------------------------------------------------ */
/* shell                                                               */
/* ------------------------------------------------------------------ */

describe("approvals page shell", () => {
  it("renders the page with title and description", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    expect(
      screen.getByRole("heading", { name: "Approvals", level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText("Review and authorize security actions")).toBeInTheDocument();
  });

  it("shows an empty state when there are no approval requests", async () => {
    stubApi(scenario([]));
    renderPage();
    expect(await screen.findByText("No approval requests")).toBeInTheDocument();
  });

  it("shows an error state with retry when the queue fails to load", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    }));
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Unable to load approval requests",
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("retry reloads the queue after a failure", async () => {
    const user = userEvent.setup();
    let fail = true;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/approvals" && !init?.method) {
        if (fail) return { ok: false, status: 500, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => [item()] };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await screen.findByRole("alert");
    fail = false;
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await tab(/^Pending/)).toBeInTheDocument();
    expect(tab(/^Pending/)).toHaveTextContent("Pending (1)");
  });

  it("renders tabs only for statuses that exist in the records", async () => {
    stubApi(
      scenario([
        item(),
        item({ approval_id: "ap-2", finding_id: FID2, status: "approved" }),
      ]),
    );
    renderPage();
    await loaded();
    expect(tab(/^Pending/)).toBeInTheDocument();
    expect(tab(/^Approved/)).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: /Rejected/ })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("tab", { name: /Changes Requested/ }),
    ).not.toBeInTheDocument();
  });

  it("shows per-tab counts", async () => {
    stubApi(
      scenario([
        item(),
        item({ approval_id: "ap-2", finding_id: FID2 }),
        item({ approval_id: "ap-3", finding_id: FID2, status: "approved" }),
      ]),
    );
    renderPage();
    await loaded();
    expect(tab(/^Pending/)).toHaveTextContent("Pending (2)");
    expect(tab(/^Approved/)).toHaveTextContent("Approved (1)");
  });
});

/* ------------------------------------------------------------------ */
/* queue table                                                         */
/* ------------------------------------------------------------------ */

describe("approval queue table", () => {
  it("renders the table columns", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const table = await screen.findByRole("table");
    for (const column of [
      "Finding",
      "Vulnerability",
      "Priority",
      "Risk",
      "Requested By",
      "Requested At",
      "Action",
      "Status",
    ]) {
      expect(within(table).getByRole("columnheader", { name: column })).toBeInTheDocument();
    }
  });

  it("renders row values from the backend record", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const table = await screen.findByRole("table");
    expect(within(table).getAllByText("SQL Injection").length).toBeGreaterThan(0);
    expect(within(table).getByText("P1")).toBeInTheDocument();
    expect(within(table).getByText("75")).toBeInTheDocument();
    expect(within(table).getByText("system")).toBeInTheDocument();
    expect(within(table).getByText("Aug 15, 2026")).toBeInTheDocument();
    expect(within(table).getByText("Remediation")).toBeInTheDocument();
    expect(within(table).getByText("Pending")).toBeInTheDocument();
  });

  it("shows the truncated finding id", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const table = await screen.findByRole("table");
    expect(within(table).getByText("a1b2c3d4\u2026")).toBeInTheDocument();
  });

  it("navigates to the finding detail page when the finding link is clicked", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const link = await screen.findByRole("link", { name: "a1b2c3d4\u2026" });
    await user.click(link);
    expect(await screen.findByText(`finding-detail-stub:${FID1}`)).toBeInTheDocument();
  });

  it("navigates with the keyboard when Enter is pressed on the finding link", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const link = await screen.findByRole("link", { name: "a1b2c3d4\u2026" });
    link.focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByText(`finding-detail-stub:${FID1}`)).toBeInTheDocument();
  });

  it("navigates when the row itself is clicked", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const row = await screen.findByRole("row", { name: /a1b2c3d4/ });
    await user.click(row);
    expect(await screen.findByText(`finding-detail-stub:${FID1}`)).toBeInTheDocument();
  });

  it("selecting an approval opens its review panel", async () => {
    const user = userEvent.setup();
    stubApi(
      scenario([
        item(),
        item({
          approval_id: "ap-2",
          finding_id: FID2,
          vulnerability_type: "command_injection",
          severity: "critical",
          priority: "P0",
          risk_score: 95,
        }),
      ]),
    );
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    expect(
      within(panel).getByRole("heading", { name: "SQL Injection" }),
    ).toBeInTheDocument();
    const table = screen.getByRole("table");
    await user.click(within(table).getByRole("button", { name: "Review" }));
    expect(
      await within(panel).findByRole("heading", { name: "Command Injection" }),
    ).toBeInTheDocument();
    expect(within(table).getAllByRole("button", { name: "Reviewing" })).toHaveLength(1);
  });

  it("terminal statuses have no review action", async () => {
    stubApi(
      scenario([
        item({ approval_id: "ap-2", finding_id: FID2, status: "approved" }),
        item({ approval_id: "ap-3", finding_id: FID2, status: "rejected" }),
      ]),
    );
    renderPage();
    await loaded();
    await screen.findByRole("table");
    expect(screen.queryByRole("button", { name: "Review" })).not.toBeInTheDocument();
    expect(screen.getAllByText("\u2014").length).toBeGreaterThanOrEqual(2);
  });

  it("switching tabs filters the queue", async () => {
    const user = userEvent.setup();
    stubApi(
      scenario([
        item(),
        item({
          approval_id: "ap-2",
          finding_id: FID2,
          status: "approved",
          vulnerability_type: "command_injection",
        }),
      ]),
    );
    renderPage();
    await loaded();
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row").length).toBe(2);
    expect(within(table).getByText("SQL Injection")).toBeInTheDocument();
    await user.click(tab(/^Approved/));
    expect(within(table).getAllByRole("row").length).toBe(2);
    expect(within(table).getByText("Command Injection")).toBeInTheDocument();
    expect(within(table).queryByText("SQL Injection")).not.toBeInTheDocument();
  });

  it("renders mobile cards as a fallback list", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    expect(screen.getByLabelText("Approval requests")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "SQL Injection" })[0]).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* review panel                                                        */
/* ------------------------------------------------------------------ */

describe("approval review panel", () => {
  it("auto-selects the first pending approval and shows PENDING REVIEW", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    expect(
      within(panel).getByRole("heading", { name: "SQL Injection" }),
    ).toBeInTheDocument();
    expect(within(panel).getByText("PENDING REVIEW")).toBeInTheDocument();
  });

  it("shows finding details", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = reviewPanel();
    expect(await within(panel).findByText("Finding")).toBeInTheDocument();
    expect(within(panel).getByText("repo-a")).toBeInTheDocument();
    expect(within(panel).getByText("users.py")).toBeInTheDocument();
    expect(within(panel).getByText("users.py:18")).toBeInTheDocument();
    expect(within(panel).getByText("users.py:27")).toBeInTheDocument();
    expect(within(panel).getByText("70%")).toBeInTheDocument();
  });

  it("shows the approval request details including the review cycle", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = reviewPanel();
    expect(await within(panel).findByText("Approval Request")).toBeInTheDocument();
    expect(within(panel).getAllByText("Cycle 1").length).toBeGreaterThan(0);
    expect(within(panel).getAllByText("system").length).toBeGreaterThan(0);
    expect(within(panel).getAllByText("Remediation").length).toBeGreaterThan(0);
  });

  it("shows the risk section with score and factors", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelAppeared();
    const risk = (await within(panel).findByText("Risk").then((el) => el.closest("section"))) as HTMLElement;
    expect(within(risk).getByText("75")).toBeInTheDocument();
    expect(within(risk).getByText("P1")).toBeInTheDocument();
    expect(within(risk).getByText("Risk Factors")).toBeInTheDocument();
  });

  it("shows the validation section", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelAppeared();
    const validation = (await within(panel).findByText("Validation").then((el) => el.closest("section"))) as HTMLElement;
    expect(within(validation).getByText("TRUE POSITIVE")).toBeInTheDocument();
  });

  it("shows the proof section with the sandbox summary", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelAppeared();
    const proof = (await within(panel).findByText("Proof").then((el) => el.closest("section"))) as HTMLElement;
    expect(within(proof).getByText("VERIFIED")).toBeInTheDocument();
    expect(
      within(proof).getByText(/Sandboxed execution confirmed/),
    ).toBeInTheDocument();
  });

  it("shows the SLA section", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelAppeared();
    const sla = (await within(panel).findByText("SLA").then((el) => el.closest("section"))) as HTMLElement;
    expect(within(sla).getByText("12h remaining")).toBeInTheDocument();
  });

  it("shows the audit history timeline", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    const history = within(panel).getByText("Audit History").closest("div") as HTMLElement;
    expect(within(history).getByText(/Request created/)).toBeInTheDocument();
    expect(within(history).getAllByText("system").length).toBeGreaterThan(0);
  });

  it("provides a link to the finding detail page", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("link", { name: "View finding detail" }));
    expect(await screen.findByText(`finding-detail-stub:${FID1}`)).toBeInTheDocument();
  });

  it("shows a hint when nothing is selected", async () => {
    stubApi(
      scenario([item({ approval_id: "ap-2", finding_id: FID2, status: "approved" })]),
    );
    renderPage();
    await loaded();
    expect(
      screen.getByText("Select an approval request from the queue to review it."),
    ).toBeInTheDocument();
  });

  it("shows a failure state with retry when review details cannot load", async () => {
    const user = userEvent.setup();
    let fail = true;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "/api/approvals" && !init?.method) {
        return { ok: true, status: 200, json: async () => [item()] };
      }
      if (fail) return { ok: false, status: 500, json: async () => ({}) };
      if (/\/approval$/.test(url)) {
        return { ok: true, status: 200, json: async () => requestOf(item()) };
      }
      if (/\/history$/.test(url)) {
        return { ok: true, status: 200, json: async () => [] };
      }
      if (/^\/api\/findings\/[^/]+$/.test(url)) {
        return { ok: true, status: 200, json: async () => findingOf(item()) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    const panel = await reviewPanelAppeared();
    expect(
      await within(panel).findByText("Unable to load the approval details."),
    ).toBeInTheDocument();
    fail = false;
    await user.click(within(panel).getByRole("button", { name: "Retry" }));
    expect(
      await within(panel).findByRole("heading", { name: "SQL Injection" }),
    ).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/* approve flow                                                        */
/* ------------------------------------------------------------------ */

describe("approve flow", () => {
  it("opens the approve modal with the finding context", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    const modal = dialog("Approve security action?");
    expect(within(modal).getByText("SQL Injection")).toBeInTheDocument();
    expect(within(modal).getByText("Remediation")).toBeInTheDocument();
    expect(within(modal).getByText("P1")).toBeInTheDocument();
  });

  it("requires a reason before confirming", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    const modal = dialog("Approve security action?");
    expect(within(modal).getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(
      within(modal).getByText("A reason is required for the audit trail."),
    ).toBeInTheDocument();
    await user.type(within(modal).getByLabelText("Reason"), "  ");
    expect(within(modal).getByRole("button", { name: "Approve" })).toBeDisabled();
  });

  it("submits the decision with reviewer and reason and closes the modal on success", async () => {
    const user = userEvent.setup();
    const scenarioData = scenario([item()]);
    const fetchMock = stubApi(scenarioData);
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified against the evidence.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));

    expect(await screen.findByRole("status")).toHaveTextContent(
      "Approval recorded successfully.",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    const posts = postsOf(fetchMock);
    expect(posts.length).toBe(1);
    const [postUrl, postInit] = posts[0];
    expect(postUrl).toBe("/api/approvals/ap-1/approve");
    expect(JSON.parse(String(postInit.body))).toEqual({
      reason: "Verified against the evidence.",
    });
  });

  it("updates the panel to Approved with the terminal note after approving", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));

    expect(
      await within(panel).findByText("Approved \u2014 action authorized."),
    ).toBeInTheDocument();
    expect(within(panel).queryByText("PENDING REVIEW")).not.toBeInTheDocument();
    expect(
      within(panel).queryByRole("button", { name: "Reject" }),
    ).not.toBeInTheDocument();
  });

  it("refreshes the audit history after a decision", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));

    const history = within(panel).getByText("Audit History").closest("div") as HTMLElement;
    expect(
      await within(history).findByText(/Pending \u2192 Approved/),
    ).toBeInTheDocument();
    expect(within(history).getAllByText("security-analyst").length).toBeGreaterThan(0);
  });

  it("prevents duplicate submissions while a decision is in flight", async () => {
    const user = userEvent.setup();
    const scenarioData = scenario([item()]);
    let resolveDecision: (r: { status: number; json: unknown }) => void = () => {};
    const gate = new Promise<{ status: number; json: unknown }>((resolve) => {
      resolveDecision = resolve;
    });
    const fetchMock = stubApi(scenarioData, (kind, body, state, approvalId) => {
      if (kind === "approve") return gate;
      return defaultDecision(kind, body, state, approvalId);
    });
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    const confirm = within(modal).getByRole("button", { name: "Approve" });
    await user.click(confirm);

    const saving = within(modal).getByRole("button", { name: "Saving\u2026" });
    expect(saving).toBeDisabled();
    expect(within(modal).getByRole("button", { name: "Cancel" })).toBeDisabled();

    resolveDecision({ status: 200, json: requestOf(item({ status: "approved" })) });
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Approval recorded successfully.",
    );
    expect(postsOf(fetchMock).length).toBe(1);
  });

  it("keeps the modal open and shows a role=alert error when the backend rejects", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]), (kind, body, state, approvalId) => {
      if (kind === "approve") {
        return {
          status: 409,
          json: { detail: "cannot transition approval from approved" },
        };
      }
      return defaultDecision(kind, body, state, approvalId);
    });
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "cannot transition approval from approved",
    );
    expect(dialog("Approve security action?")).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows a readable 422 detail when the reason is blank", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]), (kind, body, state, approvalId) => {
      if (kind === "approve") {
        return {
          status: 422,
          json: {
            detail: [{ loc: ["body", "reason"], msg: "reason must not be blank" }],
          },
        };
      }
      return defaultDecision(kind, body, state, approvalId);
    });
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "reason: reason must not be blank",
    );
  });
});

/* ------------------------------------------------------------------ */
/* reject flow                                                         */
/* ------------------------------------------------------------------ */

describe("reject flow", () => {
  it("rejects with a reason and shows the terminal note", async () => {
    const user = userEvent.setup();
    const scenarioData = scenario([item()]);
    const fetchMock = stubApi(scenarioData);
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Reject" }));
    expect(dialog("Reject security action?")).toBeInTheDocument();
    await user.type(within(dialog("Reject security action?")).getByLabelText("Reason"), "Risk accepted.");
    const modal = dialog("Reject security action?");
    await user.click(within(modal).getByRole("button", { name: "Reject" }));

    expect(
      await within(panel).findByText("Rejected \u2014 no further action."),
    ).toBeInTheDocument();
    const posts = postsOf(fetchMock);
    expect(posts.length).toBe(1);
    expect(posts[0][0]).toBe("/api/approvals/ap-1/reject");
    expect(JSON.parse(String(posts[0][1].body)).reason).toBe("Risk accepted.");
  });

  it("cancel closes the modal without submitting", async () => {
    const user = userEvent.setup();
    const scenarioData = scenario([item()]);
    const fetchMock = stubApi(scenarioData);
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Reject" }));
    const modal = dialog("Reject security action?");
    await user.type(within(modal).getByLabelText("Reason"), "Nope.");
    await user.click(within(modal).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(postsOf(fetchMock).length).toBe(0);
  });

  it("closes with Escape and restores focus to the trigger", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    const rejectButton = within(panel).getByRole("button", { name: "Reject" });
    await user.click(rejectButton);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(rejectButton).toHaveFocus();
  });
});

/* ------------------------------------------------------------------ */
/* changes requested + resubmit                                        */
/* ------------------------------------------------------------------ */

describe("changes requested and resubmit", () => {
  it("requests changes and switches the panel to the resubmit state", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Request Changes" }));
    const modal = dialog("Request changes?");
    await user.type(within(modal).getByLabelText("Reason"), "Add input validation.");
    await user.click(within(modal).getByRole("button", { name: "Request Changes" }));

    expect(
      await within(panel).findAllByText("Changes Requested").then((els) => els.length),
    ).toBeGreaterThan(0);
    expect(
      within(panel).getByText(/Additional review required/),
    ).toBeInTheDocument();
    expect(
      within(panel).getByRole("button", { name: "Resubmit for Review" }),
    ).toBeInTheDocument();
  });

  it("resubmits into a new review cycle with an incremented version", async () => {
    const user = userEvent.setup();
    stubApi(
      scenario([
        item({
          approval_id: "ap-4",
          finding_id: FID2,
          status: "changes_requested",
          reviewed_by: "security-analyst",
          reviewed_at: NOW,
          reason: "Add input validation.",
        }),
      ]),
    );
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(
      within(panel).getByRole("button", { name: "Resubmit for Review" }),
    );
    const modal = dialog("Resubmit for review?");
    await user.type(within(modal).getByLabelText("Reason"), "Input validation added.");
    await user.click(within(modal).getByRole("button", { name: "Resubmit" }));

    expect(await within(panel).findByText("PENDING REVIEW")).toBeInTheDocument();
    expect(within(panel).getAllByText("Cycle 2").length).toBeGreaterThan(0);
  });

  it("shows the Changes Requested tab for records in that status", async () => {
    stubApi(
      scenario([
        item({
          approval_id: "ap-4",
          finding_id: FID2,
          status: "changes_requested",
        }),
      ]),
    );
    renderPage();
    await loaded();
    expect(tab(/Changes Requested/)).toHaveTextContent("Changes Requested (1)");
    expect(screen.getAllByText("Changes Requested").length).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------ */
/* accessibility & security boundary                                   */
/* ------------------------------------------------------------------ */

describe("accessibility and safety", () => {
  it("marks the modal as a labelled dialog with a required reason", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Reject" }));
    const modal = dialog("Reject security action?");
    expect(modal).toHaveAttribute("aria-modal", "true");
    expect(within(modal).getByLabelText("Reason")).toHaveAttribute(
      "aria-required",
      "true",
    );
    expect(within(modal).getByLabelText("Reason")).toHaveFocus();
  });

  it("announces decisions through live regions", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));
    const status = await screen.findByRole("status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(status).toHaveTextContent("Approval recorded successfully.");
  });

  it("shows a character counter for the reason", async () => {
    const user = userEvent.setup();
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    const modal = dialog("Approve security action?");
    await user.type(within(modal).getByLabelText("Reason"), "abc");
    expect(within(modal).getByText("3/500 characters")).toBeInTheDocument();
  });

  it("never exposes remediation or execution actions", async () => {
    const user = userEvent.setup();
    const scenarioData = scenario([item()]);
    const fetchMock = stubApi(scenarioData);
    renderPage();
    await loaded();
    const panel = await reviewPanelLoaded();
    await user.click(within(panel).getByRole("button", { name: "Approve" }));
    await user.type(within(dialog("Approve security action?")).getByLabelText("Reason"), "Verified.");
    const modal = dialog("Approve security action?");
    await user.click(within(modal).getByRole("button", { name: "Approve" }));
    await screen.findByRole("status");

    const buttons = [
      ...screen.queryAllByRole("button").map((b) => b.textContent ?? ""),
      ...screen.queryAllByRole("tab").map((b) => b.textContent ?? ""),
    ];
    for (const forbidden of ["Execute", "Remediate", "Patch", "Run", "Deploy"]) {
      expect(buttons.some((label) => label.includes(forbidden))).toBe(false);
    }
    for (const [url] of postsOf(fetchMock)) {
      expect(url).toMatch(
        /^\/api\/approvals\/[^/]+\/(approve|reject|request-changes|resubmit)$/,
      );
    }
  });

  it("never issues writes through read-only endpoints", async () => {
    stubApi(scenario([item()]));
    renderPage();
    await loaded();
    const fetchCalls = vi.mocked(fetch).mock.calls;
    const reads = fetchCalls.filter(([, init]) => !init?.method || init.method === "GET");
    for (const [url] of reads) {
      expect(String(url)).not.toMatch(
        /\/approve$|\/reject$|\/request-changes$|\/resubmit$/,
      );
    }
  });
});
