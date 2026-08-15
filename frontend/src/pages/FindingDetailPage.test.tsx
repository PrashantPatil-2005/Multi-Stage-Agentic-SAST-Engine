import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FindingDetail } from "../api/findingDetail";
import { FindingDetailPage } from "./FindingDetailPage";

function detail(overrides: Partial<FindingDetail>): FindingDetail {
  return {
    finding_id: "f-sql-1",
    vulnerability_type: "sql_injection",
    severity: "high",
    scanner_confidence: 0.7,
    status: "candidate",
    repository: "repo-a",
    source: {
      file: "users.py",
      line: 18,
      snippet: 'request.args.get("id")',
      kind: "request_param",
    },
    sink: {
      file: "users.py",
      line: 27,
      snippet: "cursor.execute(query)",
      kind: "sql_execute",
    },
    taint_path: [
      {
        file: "users.py",
        line: 18,
        snippet: 'request.args.get("id")',
        step_type: "source",
      },
      {
        file: "users.py",
        line: 22,
        snippet: 'user_id = request.args.get("id")',
        step_type: "propagation",
      },
      {
        file: "users.py",
        line: 25,
        snippet: 'query = f"SELECT * FROM users WHERE id = \'{user_id}\'"',
        step_type: "string_construction",
      },
      {
        file: "users.py",
        line: 27,
        snippet: "cursor.execute(query)",
        step_type: "sink",
      },
    ],
    risk: {
      finding_id: "f-sql-1",
      vulnerability_type: "sql_injection",
      severity: "high",
      risk_score: 95,
      priority: "P0",
      factors: [
        {
          name: "severity",
          value: "high",
          points: 75,
          description: "base severity weight (HIGH = 75)",
        },
        {
          name: "validation",
          value: "true_positive",
          points: 10,
          description: "validated as a true positive (exploitable candidate)",
        },
        {
          name: "proof",
          value: "verified",
          points: 10,
          description: "sandboxed proof verified exploitability",
        },
      ],
      assessed_at: "2026-08-15T10:00:00Z",
      related_finding_ids: [],
    },
    sla: {
      status: "active",
      priority: "P0",
      started_at: "2026-08-15T09:00:00Z",
      due_at: "2026-08-15T21:00:00Z",
      breached_at: null,
      resolved_at: null,
      escalation_level: 0,
      remaining_seconds: 43200,
    },
    validation: {
      finding_id: "f-sql-1",
      verdict: "true_positive",
      confidence: 0.94,
      reasoning:
        "The value flows from request.args into an f-string SQL query executed by cursor.execute without sanitization.",
      evidence_used: ["source_snippet", "sink_snippet", "taint_path"],
      missing_evidence: [],
      recommended_next_step: "prove",
      model: "fake-model",
      validated_at: "2026-08-15T10:30:00Z",
    },
    proof: {
      status: "verified",
      confidence: 0.99,
      summary:
        "Sandboxed execution confirmed the constructed SQL statement reaches the sink.",
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
    approval: {
      id: "ap-1",
      finding_id: "f-sql-1",
      status: "pending",
      requested_at: "2026-08-15T11:05:00Z",
      requested_by: "system",
      reviewed_at: null,
      reviewed_by: null,
      reason: null,
      action: "remediation",
      version: 1,
    },
    dedup: {
      fingerprint: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
      structural_signature: "sql_injection:request_param->sql_execute",
      is_canonical: true,
      canonical_finding_id: "f-sql-1",
      occurrence_count: 3,
      related_finding_ids: [],
    },
    ...overrides,
  };
}

function mockDetail(payload: unknown, status = 200) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL) => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function renderPage(initialEntry = "/findings/f-sql-1") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/findings" element={<div>list-page</div>} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

function header() {
  return screen.getByRole("heading", { level: 1 }).closest(".fd-header") as HTMLElement;
}

function panel(title: string) {
  return screen.getByText(title).closest("section") as HTMLElement;
}

async function loaded() {
  await screen.findByRole("heading", { level: 1 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("finding detail page", () => {
  it("renders the finding detail page", async () => {
    mockDetail(detail({}));
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "SQL Injection" }),
    ).toBeInTheDocument();
  });

  it("renders the finding header with back navigation and title", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(
      screen.getByRole("link", { name: "Back to Findings" }),
    ).toHaveAttribute("href", "/findings");
    expect(
      screen.getByRole("heading", { name: "SQL Injection", level: 1 }),
    ).toBeInTheDocument();
  });

  it("displays the priority", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("P0")).toBeInTheDocument();
  });

  it("displays the severity", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("HIGH")).toBeInTheDocument();
  });

  it("displays the current derived status", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("Pending Approval")).toBeInTheDocument();
  });

  it("derives the Proven status with the Phase 3 precedence", async () => {
    mockDetail(
      detail({
        approval: null,
        validation: {
          ...detail({}).validation!,
        },
      }),
    );
    renderPage();
    await loaded();
    expect(within(header()).getByText("Proven")).toBeInTheDocument();
  });

  it("displays the finding ID", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("f-sql-1")).toBeInTheDocument();
  });

  it("displays the repository", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("repo-a")).toBeInTheDocument();
  });

  it("displays the file", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(within(header()).getByText("users.py")).toBeInTheDocument();
  });

  it("displays the source", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(
      within(header()).getAllByText('request.args.get("id")').length,
    ).toBeGreaterThan(0);
  });

  it("displays the sink", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(
      within(header()).getAllByText("cursor.execute(query)").length,
    ).toBeGreaterThan(0);
  });

  it("shows em dashes for unavailable metadata", async () => {
    mockDetail(detail({ repository: null }));
    renderPage();
    await loaded();
    expect(within(header()).getAllByText("—").length).toBeGreaterThan(0);
  });

  it("renders the taint path steps with types and line numbers", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const taint = screen.getByLabelText("Taint path");
    expect(within(taint).getByText("SOURCE")).toBeInTheDocument();
    expect(within(taint).getByText("PROPAGATION")).toBeInTheDocument();
    expect(
      within(taint).getByText("STRING CONSTRUCTION"),
    ).toBeInTheDocument();
    expect(within(taint).getByText("SINK")).toBeInTheDocument();
    expect(within(taint).getByText("18")).toBeInTheDocument();
    expect(within(taint).getByText("22")).toBeInTheDocument();
    expect(within(taint).getByText("25")).toBeInTheDocument();
    expect(within(taint).getByText("27")).toBeInTheDocument();
    expect(
      within(taint).getByText('user_id = request.args.get("id")'),
    ).toBeInTheDocument();
  });

  it("shows no-taint-path message when no steps exist", async () => {
    mockDetail(detail({ taint_path: [] }));
    renderPage();
    await loaded();
    expect(screen.getByText("No taint path available")).toBeInTheDocument();
  });

  it("shows the source panel details", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const sourcePanel = screen.getByLabelText("Source");
    expect(within(sourcePanel).getByText("request_param")).toBeInTheDocument();
    expect(within(sourcePanel).getByText("users.py:18")).toBeInTheDocument();
  });

  it("shows the sink panel details", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const sinkPanel = screen.getByLabelText("Sink");
    expect(within(sinkPanel).getByText("sql_execute")).toBeInTheDocument();
    expect(within(sinkPanel).getByText("users.py:27")).toBeInTheDocument();
  });

  it("renders the deduplication group", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Deduplication");
    expect(within(section).getByText("Canonical finding")).toBeInTheDocument();
  });

  it("renders the occurrence count", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Deduplication");
    expect(within(section).getByText("3")).toBeInTheDocument();
    expect(within(section).getByText(/^a1b2c3d4e5f6a1b2…$/)).toBeInTheDocument();
  });

  it("renders clickable related findings when not canonical", async () => {
    mockDetail(
      detail({
        dedup: {
          ...detail({}).dedup!,
          is_canonical: false,
          canonical_finding_id: "f-sql-0",
          related_finding_ids: ["f-sql-2", "f-sql-3"],
        },
      }),
    );
    renderPage();
    await loaded();
    const section = panel("Deduplication");
    expect(within(section).getByText("f-sql-0")).toHaveAttribute(
      "href",
      "/findings/f-sql-0",
    );
    expect(within(section).getByText("f-sql-2")).toHaveAttribute(
      "href",
      "/findings/f-sql-2",
    );
    expect(within(section).getByText("f-sql-3")).toHaveAttribute(
      "href",
      "/findings/f-sql-3",
    );
  });

  it("shows no-duplicate-group when dedup data is missing", async () => {
    mockDetail(detail({ dedup: null }));
    renderPage();
    await loaded();
    expect(screen.getByText("No duplicate group")).toBeInTheDocument();
  });

  it("renders the risk score and priority", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Risk");
    expect(within(section).getByText("95")).toBeInTheDocument();
    expect(within(section).getByText("/ 100")).toBeInTheDocument();
    expect(within(section).getByText("P0")).toBeInTheDocument();
  });

  it("renders risk factors", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Risk");
    expect(within(section).getByText("severity")).toBeInTheDocument();
    expect(within(section).getByText("true_positive")).toBeInTheDocument();
    expect(within(section).getByText("75 pts")).toBeInTheDocument();
  });

  it("shows unavailable risk when no assessment exists", async () => {
    mockDetail(detail({ risk: null, sla: null }));
    renderPage();
    await loaded();
    expect(
      screen.getByText("Risk assessment not available"),
    ).toBeInTheDocument();
  });

  it("renders the active SLA with remaining time", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("SLA");
    expect(within(section).getByText("Active")).toBeInTheDocument();
    expect(within(section).getByText("12h remaining")).toBeInTheDocument();
    expect(within(section).getByText("P0")).toBeInTheDocument();
  });

  it("renders a breached SLA with escalation level", async () => {
    mockDetail(
      detail({
        sla: {
          ...detail({}).sla!,
          status: "breached",
          breached_at: "2026-08-15T13:00:00Z",
          remaining_seconds: null,
          escalation_level: 1,
        },
      }),
    );
    renderPage();
    await loaded();
    const section = panel("SLA");
    expect(within(section).getByText("SLA BREACHED")).toBeInTheDocument();
    expect(within(section).getByText("Level 1")).toBeInTheDocument();
  });

  it("renders the validation verdict and confidence", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Validation");
    expect(within(section).getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(within(section).getByText("94%")).toBeInTheDocument();
  });

  it("renders validation reasoning when available", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Validation");
    expect(
      within(section).getByText(/The value flows from request\.args into an f-string/),
    ).toBeInTheDocument();
  });

  it("shows a fallback when validation reasoning is missing", async () => {
    mockDetail(detail({ validation: { ...detail({}).validation!, reasoning: "" } }));
    renderPage();
    await loaded();
    expect(
      screen.getByText("No validation reasoning available"),
    ).toBeInTheDocument();
  });

  it("renders the proof status and summary", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Proof");
    expect(within(section).getByText("VERIFIED")).toBeInTheDocument();
    expect(
      within(section).getByText(
        "Sandboxed execution confirmed the constructed SQL statement reaches the sink.",
      ),
    ).toBeInTheDocument();
  });

  it("renders the approval state", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Human Approval");
    expect(within(section).getByText("Pending")).toBeInTheDocument();
    expect(within(section).getByText("Approval required")).toBeInTheDocument();
    expect(within(section).getByText("system")).toBeInTheDocument();
  });

  it("renders a reviewed approval with reason", async () => {
    mockDetail(
      detail({
        approval: {
          ...detail({}).approval!,
          status: "approved",
          reviewed_at: "2026-08-15T12:00:00Z",
          reviewed_by: "security-lead",
          reason: "verified",
        },
      }),
    );
    renderPage();
    await loaded();
    const section = panel("Human Approval");
    expect(within(section).getByText("Approved")).toBeInTheDocument();
    expect(within(section).getByText("security-lead")).toBeInTheDocument();
    expect(within(section).getByText("verified")).toBeInTheDocument();
  });

  it("expands the raw finding JSON on demand", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const details = screen
      .getByText("Expand raw finding metadata")
      .closest("details")!;
    expect(details.hasAttribute("open")).toBe(false);
    await userEvent.click(screen.getByText("Expand raw finding metadata"));
    expect(details.hasAttribute("open")).toBe(true);
    const raw = screen.getByLabelText("Raw finding JSON");
    expect(within(raw).getByText(/"finding_id": "f-sql-1"/)).toBeInTheDocument();
  });

  it("handles missing optional data without fabrication", async () => {
    mockDetail(
      detail({
        risk: null,
        sla: null,
        validation: null,
        proof: null,
        approval: null,
        dedup: null,
        taint_path: [],
      }),
    );
    renderPage();
    await loaded();
    expect(within(header()).getByText("Detected")).toBeInTheDocument();
    expect(screen.getByText("Risk assessment not available")).toBeInTheDocument();
    expect(screen.getByText("No SLA")).toBeInTheDocument();
    expect(screen.getByText("Not validated")).toBeInTheDocument();
    expect(screen.getByText("No proof result")).toBeInTheDocument();
    expect(screen.getByText("No approval request")).toBeInTheDocument();
    expect(screen.getByText("No duplicate group")).toBeInTheDocument();
    expect(screen.getByText("No taint path available")).toBeInTheDocument();
    expect(screen.getAllByText("Not completed").length).toBeGreaterThanOrEqual(4);
    expect(screen.queryByText("0%")).not.toBeInTheDocument();
  });

  it("shows a structured skeleton while loading", async () => {
    const fetchMock = vi.fn(
      () =>
        new Promise<never>(() => {
          /* never resolves during the test */
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await waitFor(() => {
      expect(document.querySelectorAll(".fd-skeleton").length).toBeGreaterThan(0);
    });
    expect(
      screen.getByLabelText("Loading finding detail"),
    ).toBeInTheDocument();
    expect(screen.queryByText("SQL Injection")).not.toBeInTheDocument();
  });

  it("shows an API error state with Retry", async () => {
    let failing = true;
    const fetchMock = vi.fn(async () => {
      if (failing) throw new Error("network down");
      return { ok: true, status: 200, json: async () => detail({}) };
    });
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    expect(
      await screen.findByRole("alert", { name: "Finding load error" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Unable to load finding.")).toBeInTheDocument();

    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    await loaded();
    expect(
      screen.getByRole("heading", { name: "SQL Injection" }),
    ).toBeInTheDocument();
  });

  it("shows a not-found state for an unknown finding", async () => {
    mockDetail({ detail: "finding not found" }, 404);
    renderPage("/findings/does-not-exist");
    expect(
      await screen.findByRole("alert", { name: "Finding not found" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Finding not found")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to Findings" }),
    ).toHaveAttribute("href", "/findings");
  });

  it("navigates back to the findings list", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    await userEvent.click(screen.getByRole("link", { name: "Back to Findings" }));
    expect(await screen.findByText("list-page")).toBeInTheDocument();
  });

  it("renders without horizontal overflow on mobile", async () => {
    Object.defineProperty(window, "innerWidth", {
      configurable: true,
      value: 390,
    });
    mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(
      document.documentElement.clientWidth,
    );
  });

  it("never displays dangerous proof payloads", async () => {
    const dangerous = {
      ...detail({}),
      input_value: "rm -rf /tmp/evil",
      artifacts: [
        {
          name: "payload",
          kind: "sql_statement",
          content: "SELECT 'pwned'; DROP TABLE users;",
        },
      ],
    } as FindingDetail;
    mockDetail(dangerous);
    renderPage();
    await loaded();
    const proofSection = panel("Proof");
    expect(within(proofSection).queryByText("rm -rf /tmp/evil")).not.toBeInTheDocument();
    expect(within(proofSection).queryByText(/DROP TABLE users/)).not.toBeInTheDocument();
    expect(document.querySelectorAll("script, iframe, object").length).toBe(0);
    const raw = screen
      .getByText("Expand raw finding metadata")
      .closest("details")!;
    expect(raw.hasAttribute("open")).toBe(false);
  });

  it("only fetches the finding detail endpoint (read-only, no LLM/shell/fs)", async () => {
    const fetchMock = mockDetail(detail({}));
    renderPage();
    await loaded();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/findings/f-sql-1");
  });
});
