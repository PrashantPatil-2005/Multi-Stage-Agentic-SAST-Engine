import { readFileSync } from "node:fs";

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ApprovalEvent, ApprovalRequest } from "../api/approvals";
import type { FindingDetail } from "../api/findingDetail";
import type { ScanRun } from "../api/scans";
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
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    if (status !== 200) {
      return { ok: false, status, json: async () => payload };
    }
    if (url === "/api/findings/f-sql-1") {
      return { ok: true, status: 200, json: async () => payload };
    }
    if (url === "/api/findings/f-sql-1/approval") {
      const p = payload as FindingDetail;
      if (p.approval) {
        return { ok: true, status: 200, json: async () => p.approval };
      }
      return {
        ok: false,
        status: 404,
        json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
      };
    }
    if (url === "/api/approvals/ap-1/history") {
      return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
    }
    return { ok: false, status: 404, json: async () => ({ detail: "not found" }) };
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const APPROVAL_HISTORY: ApprovalEvent[] = [
  {
    id: "ev-1",
    approval_id: "ap-1",
    finding_id: "f-sql-1",
    previous_status: null,
    new_status: "pending",
    actor: "system",
    reason: null,
    created_at: "2026-08-15T11:05:00Z",
  },
];

const RISK_OUT = {
  finding_id: "f-sql-1",
  vulnerability_type: "sql_injection",
  severity: "high",
  risk_score: 88,
  priority: "P1",
  factors: [
    {
      name: "severity",
      value: "high",
      points: 75,
      description: "base severity weight (HIGH = 75)",
    },
    {
      name: "validation",
      value: "none",
      points: 0,
      description: "no validation result yet",
    },
  ],
  assessed_at: "2026-08-16T10:00:00Z",
  related_finding_ids: [],
};

const SLA_OUT = {
  finding_id: "f-sql-1",
  priority: "P1",
  started_at: "2026-08-16T10:00:00Z",
  due_at: "2026-08-17T10:00:00Z",
  status: "active",
  breached_at: null,
  escalation_level: 0,
  last_checked_at: "2026-08-16T10:00:00Z",
  resolved_at: null,
};

const CHECK_OUT = {
  sla: {
    ...SLA_OUT,
    status: "breached",
    breached_at: "2026-08-16T12:00:00Z",
    escalation_level: 1,
    last_checked_at: "2026-08-16T12:00:00Z",
  },
  escalation: {
    finding_id: "f-sql-1",
    previous_level: 0,
    new_level: 1,
    reason: "SLA breached for P1: due 2026-08-17T10:00:00Z exceeded",
    created_at: "2026-08-16T12:00:00Z",
  },
};

interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

function mockRiskFlow(options: {
  detail: FindingDetail;
  afterAssess?: FindingDetail;
  afterStartSla?: FindingDetail;
  afterCheckSla?: FindingDetail;
  riskResponses?: MockResponse[];
  slaResponses?: MockResponse[];
  checkResponses?: MockResponse[];
  delayMs?: number;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let riskDone = false;
  let slaDone = false;
  let checkDone = false;
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      const selected = () =>
        checkDone && options.afterCheckSla
          ? options.afterCheckSla
          : slaDone && options.afterStartSla
            ? options.afterStartSla
            : riskDone && options.afterAssess
              ? options.afterAssess
              : options.detail;
      if (method === "GET" && url === "/api/findings/f-sql-1") {
        return { ok: true, status: 200, json: async () => selected() };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
        const approval = (selected() as FindingDetail).approval;
        if (approval) {
          return { ok: true, status: 200, json: async () => approval };
        }
        return {
          ok: false,
          status: 404,
          json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
        };
      }
      if (method === "GET" && url === "/api/approvals/ap-1/history") {
        return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
      }
      const consume = async (
        responses: MockResponse[] | undefined,
        success: () => Promise<unknown>,
      ): Promise<MockResponse> => {
        if (options.delayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.delayMs));
        }
        if (responses && responses.length > 0) {
          return responses.shift() as MockResponse;
        }
        return { ok: true, status: 200, json: success };
      };
      if (method === "POST" && url === "/api/findings/f-sql-1/risk") {
        const response = await consume(options.riskResponses, async () => RISK_OUT);
        if (response.ok) riskDone = true;
        return response;
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/sla") {
        const response = await consume(options.slaResponses, async () => SLA_OUT);
        if (response.ok) slaDone = true;
        return response;
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/sla/check") {
        const response = await consume(options.checkResponses, async () => CHECK_OUT);
        if (response.ok) checkDone = true;
        return response;
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const VALIDATION_OUT = {
  finding_id: "f-sql-1",
  verdict: "true_positive",
  confidence: 0.91,
  reasoning:
    "The taint path from request.args reaches cursor.execute with no sanitizer in between; the payload is fully attacker-controlled.",
  evidence_used: [
    "source_snippet",
    "sink_snippet",
    "taint_path",
    "sanitizer_observations",
  ],
  missing_evidence: [],
  recommended_next_step: "prove",
  model: "fake-model-2",
  validated_at: "2026-08-16T10:30:00Z",
};

function mockValidateFlow(options: {
  detail: FindingDetail;
  afterValidate?: FindingDetail;
  validateResponses?: MockResponse[];
  delayMs?: number;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let validatedDone = false;
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      if (method === "GET" && url === "/api/findings/f-sql-1") {
        const payload =
          validatedDone && options.afterValidate
            ? options.afterValidate
            : options.detail;
        return { ok: true, status: 200, json: async () => payload };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
        const approval = (
          (validatedDone && options.afterValidate ? options.afterValidate : options.detail) as FindingDetail
        ).approval;
        if (approval) {
          return { ok: true, status: 200, json: async () => approval };
        }
        return {
          ok: false,
          status: 404,
          json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
        };
      }
      if (method === "GET" && url === "/api/approvals/ap-1/history") {
        return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
      }
      if (options.delayMs) {
        await new Promise((resolve) => setTimeout(resolve, options.delayMs));
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/validate") {
        if (options.validateResponses && options.validateResponses.length > 0) {
          const response = options.validateResponses.shift() as MockResponse;
          if (response.ok) validatedDone = true;
          return response;
        }
        validatedDone = true;
        return { ok: true, status: 200, json: async () => VALIDATION_OUT };
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const PROOF_OUT = {
  finding_id: "f-sql-1",
  vulnerability_type: "sql_injection",
  status: "verified",
  confidence: 0.94,
  summary:
    "unsafe string construction returned 2 rows while the parameterized construction returned 0 rows for the same benign marker in the local fixture",
  duration_ms: 4567,
  sandbox_policy: {
    network_enabled: false,
    allow_loopback: false,
    allowed_paths: [],
    timeout_seconds: 10,
    max_output_bytes: 16384,
    max_processes: 1,
    temporary_directory: "",
  },
  error: null,
  created_at: "2026-08-16T11:00:00Z",
};

function mockProveFlow(options: {
  detail: FindingDetail;
  afterProve?: FindingDetail;
  proveResponses?: MockResponse[];
  delayMs?: number;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let proveDone = false;
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      if (method === "GET" && url === "/api/findings/f-sql-1") {
        const payload =
          proveDone && options.afterProve ? options.afterProve : options.detail;
        return { ok: true, status: 200, json: async () => payload };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
        const approval = (
          (proveDone && options.afterProve ? options.afterProve : options.detail) as FindingDetail
        ).approval;
        if (approval) {
          return { ok: true, status: 200, json: async () => approval };
        }
        return {
          ok: false,
          status: 404,
          json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
        };
      }
      if (method === "GET" && url === "/api/approvals/ap-1/history") {
        return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
      }
      if (options.delayMs) {
        await new Promise((resolve) => setTimeout(resolve, options.delayMs));
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/prove") {
        if (options.proveResponses && options.proveResponses.length > 0) {
          const response = options.proveResponses.shift() as MockResponse;
          if (response.ok) proveDone = true;
          return response;
        }
        proveDone = true;
        return { ok: true, status: 200, json: async () => PROOF_OUT };
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function proofSection() {
  return panel("Proof");
}

function proveFixture(overrides: Partial<FindingDetail["proof"]>) {
  return detail({
    validation: detail({}).validation,
    proof: { ...detail({}).proof!, ...overrides } as FindingDetail["proof"],
  });
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

function riskSection() {
  return panel("Risk");
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

  it("explains that proof shows a safe summary, not raw artifacts", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Proof");
    expect(
      within(section).getByText(
        /Raw payloads, artifacts and sandbox internals are intentionally not exposed/,
      ),
    ).toBeInTheDocument();
    expect(within(section).queryByText(/DROP TABLE users/)).not.toBeInTheDocument();
    expect(within(section).queryByText("temporary_directory")).not.toBeInTheDocument();
  });

  it("renders the approval state", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = panel("Human Approval");
    expect(within(section).getByText("Pending")).toBeInTheDocument();
    expect(within(section).getByText("Approval required")).toBeInTheDocument();
    expect(within(section).getAllByText("system").length).toBeGreaterThan(0);
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
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (failing) throw new Error("network down");
      const url = String(input);
      if (url === "/api/approvals/ap-1/history") {
        return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
      }
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

  it("only issues read-only requests on page load (no LLM/shell/fs)", async () => {
    const fetchMock = mockDetail(detail({}));
    renderPage();
    await loaded();
    const calls = fetchMock.mock.calls.map(([input, init]) => [
      String(input),
      (init?.method ?? "GET").toUpperCase(),
    ]);
    for (const [, method] of calls) {
      expect(method).toBe("GET");
    }
    expect(calls).toEqual(
      expect.arrayContaining([
        ["/api/findings/f-sql-1", "GET"],
        ["/api/findings/f-sql-1/approval", "GET"],
        ["/api/approvals/ap-1/history", "GET"],
      ]),
    );
  });
});

describe("finding lineage (repository and scan runs)", () => {
  const PROJECT = {
    project_id: "aaaa0000aaaa0000aaaa0000aaaa0000",
    name: "web-app",
    source_type: "git",
    location: "https://github.com/example/web-app",
    language: "python",
  };

  const RUN_1: ScanRun = {
    scan_run_id: "scan-run-0001",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T07:10:00Z",
    completed_at: "2026-08-16T07:10:05Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T07:10:00Z",
  };

  const RUN_2: ScanRun = {
    scan_run_id: "scan-run-0002",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T08:20:00Z",
    completed_at: "2026-08-16T08:20:04Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T08:20:00Z",
  };

  function lineageSection() {
    return panel("Repository & Scan Lineage");
  }

  it("displays the owning repository from the authoritative backend lineage", async () => {
    mockDetail(detail({ project: PROJECT, scan_runs: [RUN_1] }));
    renderPage();
    await loaded();
    const section = lineageSection();
    expect(within(section).getByText("web-app")).toBeInTheDocument();
    expect(within(section).getByText("python")).toBeInTheDocument();
    expect(within(section).getByText("git")).toBeInTheDocument();
    expect(
      within(section).getByRole("link", { name: "Open Repository" }),
    ).toHaveAttribute(
      "href",
      `/repositories?project_id=${PROJECT.project_id}`,
    );
  });

  it("links the header repository to the real project id", async () => {
    mockDetail(detail({ project: PROJECT, scan_runs: [] }));
    renderPage();
    await loaded();
    const repositoryLink = within(header()).getByRole("link", {
      name: "web-app",
    });
    expect(repositoryLink).toHaveAttribute(
      "href",
      `/repositories?project_id=${PROJECT.project_id}`,
    );
  });

  it("lists every producing scan run with a link to the real run id", async () => {
    mockDetail(detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1] }));
    renderPage();
    await loaded();
    const section = lineageSection();
    const runLinks = within(section).getAllByRole("link", {
      name: /Scan run scan-run-/,
    });
    expect(runLinks).toHaveLength(2);
    expect(runLinks[0]).toHaveAttribute("href", "/scans/scan-run-0002");
    expect(runLinks[1]).toHaveAttribute("href", "/scans/scan-run-0001");
    expect(within(section).getAllByText("completed")).toHaveLength(2);
  });

  it("shows honest lineage-unavailable states when lineage is missing", async () => {
    mockDetail(detail({ project: null, scan_runs: [] }));
    renderPage();
    await loaded();
    const section = lineageSection();
    expect(
      within(section).getByText("Repository lineage unavailable."),
    ).toBeInTheDocument();
    expect(
      within(section).getByText("Scan lineage unavailable."),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("link", { name: "Open Repository" }),
    ).not.toBeInTheDocument();
  });

  it("never derives repository or scan links from paths or timestamps", async () => {
    mockDetail(detail({ project: PROJECT, scan_runs: [RUN_1] }));
    renderPage();
    await loaded();
    const section = lineageSection();
    const links = within(section).getAllByRole("link");
    for (const link of links) {
      const href = link.getAttribute("href") ?? "";
      if (href.startsWith("/scans/")) {
        expect(href).toBe("/scans/scan-run-0001");
      }
      if (href.startsWith("/repositories")) {
        expect(href).toBe(
          `/repositories?project_id=${PROJECT.project_id}`,
        );
      }
    }
    const source = readFileSync(
      "src/components/finding-detail/LineagePanel.tsx",
      "utf-8",
    );
    expect(source).not.toContain("Math.random");
    expect(source).not.toContain("setInterval");
    expect(source).not.toContain("child_process");
  });
});

describe("finding run context (Phase 14J)", () => {
  const PROJECT = {
    project_id: "aaaa0000aaaa0000aaaa0000aaaa0000",
    name: "web-app",
    source_type: "git",
    location: "https://github.com/example/web-app",
    language: "python",
  };

  const RUN_1: ScanRun = {
    scan_run_id: "scan-run-0001",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T07:10:00Z",
    completed_at: "2026-08-16T07:10:05Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T07:10:00Z",
  };

  const RUN_2: ScanRun = {
    scan_run_id: "scan-run-0002",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T08:20:00Z",
    completed_at: "2026-08-16T08:20:04Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T08:20:00Z",
  };

  function riskPosts(onCall: ReturnType<typeof vi.fn>) {
    return onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/risk" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
  }

  it("uses its only producing scan run automatically and sends its exact id", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ project: PROJECT, scan_runs: [RUN_1], risk: null, sla: null }),
      afterAssess: detail({
        project: PROJECT,
        scan_runs: [RUN_1],
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: null,
      }),
      onCall,
    });
    renderPage();
    await loaded();
    const context = screen.getByText("Run context");
    expect(context.closest(".fd-runcontext")?.textContent).toContain(
      "#scan-run",
    );
    await user.click(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    );
    await within(riskSection()).findByRole("status");
    const post = riskPosts(onCall)[0];
    expect(post).toBeDefined();
    expect(JSON.parse(String(post[1]?.body))).toEqual({
      scan_run_id: RUN_1.scan_run_id,
    });
  });

  it("requires an explicit run context when several runs produced the finding", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1], risk: null, sla: null }),
      afterAssess: detail({
        project: PROJECT,
        scan_runs: [RUN_2, RUN_1],
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: null,
      }),
      onCall,
    });
    renderPage();
    await loaded();
    const select = screen.getByLabelText("Scan run context");
    expect(select).toHaveValue("");
    const assess = within(riskSection()).getByRole("button", {
      name: "Assess Risk",
    });
    expect(assess).toBeDisabled();
    expect(riskPosts(onCall)).toHaveLength(0);

    await user.selectOptions(select, RUN_2.scan_run_id);
    expect(select).toHaveValue(RUN_2.scan_run_id);
    expect(assess).toBeEnabled();
    await user.click(assess);
    await within(riskSection()).findByRole("status");
    const post = riskPosts(onCall)[0];
    expect(post).toBeDefined();
    expect(JSON.parse(String(post[1]?.body))).toEqual({
      scan_run_id: RUN_2.scan_run_id,
    });
  });

  it("selects only the real backend scan-run ids from lineage", async () => {
    mockRiskFlow({
      detail: detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1], risk: null, sla: null }),
    });
    renderPage();
    await loaded();
    const select = screen.getByLabelText("Scan run context") as HTMLSelectElement;
    const values = Array.from(select.options).map((option) => option.value);
    expect(values).toEqual(["", RUN_2.scan_run_id, RUN_1.scan_run_id]);
  });

  it("keeps SLA actions disabled until a run context is chosen", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({
        project: PROJECT,
        scan_runs: [RUN_2, RUN_1],
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: null,
      }),
    });
    renderPage();
    await loaded();
    expect(
      within(panel("SLA")).getByRole("button", { name: "Start SLA" }),
    ).toBeDisabled();
    const select = screen.getByLabelText("Scan run context");
    await user.selectOptions(select, RUN_1.scan_run_id);
    expect(
      within(panel("SLA")).getByRole("button", { name: "Start SLA" }),
    ).toBeEnabled();
  });

  it("sends no run context when the finding has no scan runs", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ project: PROJECT, scan_runs: [], risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      onCall,
    });
    renderPage();
    await loaded();
    expect(screen.queryByText("Run context")).not.toBeInTheDocument();
    await user.click(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    );
    await within(riskSection()).findByRole("status");
    const post = riskPosts(onCall)[0];
    expect(post).toBeDefined();
    expect(post[1]?.body).toBeUndefined();
  });
});

describe("finding full pipeline run context (Phase 14K)", () => {
  const PROJECT = {
    project_id: "aaaa0000aaaa0000aaaa0000aaaa0000",
    name: "web-app",
    source_type: "git",
    location: "https://github.com/example/web-app",
    language: "python",
  };

  const RUN_1: ScanRun = {
    scan_run_id: "scan-run-0001",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T07:10:00Z",
    completed_at: "2026-08-16T07:10:05Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T07:10:00Z",
  };

  const RUN_2: ScanRun = {
    scan_run_id: "scan-run-0002",
    project_id: PROJECT.project_id,
    status: "completed",
    started_at: "2026-08-16T08:20:00Z",
    completed_at: "2026-08-16T08:20:04Z",
    scanned_file_count: 127,
    total_findings: 3,
    error: null,
    created_at: "2026-08-16T08:20:00Z",
  };

  function validatePosts(onCall: ReturnType<typeof vi.fn>) {
    return onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/validate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
  }

  function provePosts(onCall: ReturnType<typeof vi.fn>) {
    return onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/prove" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
  }

  it("validate sends the exact selected scan_run_id with one run", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ project: PROJECT, scan_runs: [RUN_1], validation: null }),
      afterValidate: detail({ project: PROJECT, scan_runs: [RUN_1] }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Validation")).getByRole("button", { name: "Validate" }),
    );
    await within(panel("Validation")).findByRole("status");
    const post = validatePosts(onCall)[0];
    expect(post).toBeDefined();
    expect(JSON.parse(String(post[1]?.body))).toEqual({
      provider: "huggingface",
      scan_run_id: RUN_1.scan_run_id,
    });
  });

  it("prove sends the exact selected scan_run_id with one run", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({
        project: PROJECT,
        scan_runs: [RUN_1],
        validation: { ...detail({}).validation! },
        proof: null,
      }),
      afterProve: detail({ project: PROJECT, scan_runs: [RUN_1] }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Proof")).getByRole("button", { name: "Prove Finding" }),
    );
    await within(panel("Proof")).findByRole("status");
    const post = provePosts(onCall)[0];
    expect(post).toBeDefined();
    expect(JSON.parse(String(post[1]?.body))).toEqual({
      scan_run_id: RUN_1.scan_run_id,
    });
  });

  it("request approval sends the exact selected scan_run_id with one run", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    const payload = detail({
      project: PROJECT,
      scan_runs: [RUN_1],
      approval: null,
    });
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        onCall(url, init);
        if (method === "GET" && url === "/api/findings/f-sql-1") {
          return { ok: true, status: 200, json: async () => payload };
        }
        if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
          return {
            ok: false,
            status: 404,
            json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
          };
        }
        if (method === "POST" && url === "/api/findings/f-sql-1/approval") {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              id: "ap-14k",
              finding_id: "f-sql-1",
              status: "pending",
              requested_at: "2026-08-16T09:00:00Z",
              requested_by: "system",
              reviewed_at: null,
              reviewed_by: null,
              reason: null,
              action: "remediation",
              version: 1,
              scan_run_id: RUN_1.scan_run_id,
            }),
          };
        }
        throw new Error(`unexpected request: ${method} ${url}`);
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await loaded();
    await user.click(
      within(panel("Human Approval")).getByRole("button", {
        name: "Request Approval",
      }),
    );
    await waitFor(() => {
      expect(
        onCall.mock.calls.some(
          ([url, requestInit]) =>
            String(url) === "/api/findings/f-sql-1/approval" &&
            (requestInit?.method ?? "").toUpperCase() === "POST",
        ),
      ).toBe(true);
    });
    const post = onCall.mock.calls.find(
      ([url, requestInit]) =>
        String(url) === "/api/findings/f-sql-1/approval" &&
        (requestInit?.method ?? "").toUpperCase() === "POST",
    );
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({
      action: "remediation",
      requested_by: "system",
      scan_run_id: RUN_1.scan_run_id,
    });
  });

  it("disables Validate until a run context is selected with multiple runs", async () => {
    const user = userEvent.setup();
    mockValidateFlow({
      detail: detail({
        project: PROJECT,
        scan_runs: [RUN_2, RUN_1],
        validation: null,
      }),
      afterValidate: detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1] }),
    });
    renderPage();
    await loaded();
    const validate = within(panel("Validation")).getByRole("button", {
      name: "Validate",
    });
    expect(validate).toBeDisabled();
    const select = screen.getByLabelText("Scan run context");
    await user.selectOptions(select, RUN_2.scan_run_id);
    expect(validate).toBeEnabled();
  });

  it("disables Prove Finding until a run context is selected", async () => {
    const user = userEvent.setup();
    mockProveFlow({
      detail: detail({
        project: PROJECT,
        scan_runs: [RUN_2, RUN_1],
        validation: { ...detail({}).validation! },
        proof: null,
      }),
      afterProve: detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1] }),
    });
    renderPage();
    await loaded();
    const prove = within(panel("Proof")).getByRole("button", {
      name: "Prove Finding",
    });
    expect(prove).toBeDisabled();
    const select = screen.getByLabelText("Scan run context");
    await user.selectOptions(select, RUN_2.scan_run_id);
    expect(prove).toBeEnabled();
  });

  it("disables Request Approval until a run context is selected", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url === "/api/findings/f-sql-1") {
          return {
            ok: true,
            status: 200,
            json: async () =>
              detail({ project: PROJECT, scan_runs: [RUN_2, RUN_1], approval: null }),
          };
        }
        if (url === "/api/findings/f-sql-1/approval") {
          return {
            ok: false,
            status: 404,
            json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
          };
        }
        throw new Error(`unexpected request: ${url}`);
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await loaded();
    const requestApproval = within(panel("Human Approval")).getByRole("button", {
      name: "Request Approval",
    });
    expect(requestApproval).toBeDisabled();
    const select = screen.getByLabelText("Scan run context");
    await user.selectOptions(select, RUN_2.scan_run_id);
    expect(requestApproval).toBeEnabled();
  });

  it("shares one run context across risk and validate actions", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    let riskDone = false;
    let validateDone = false;
    const fetchMock = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        onCall(url, init);
        if (method === "GET" && url === "/api/findings/f-sql-1") {
          const current = validateDone
            ? detail({
                project: PROJECT,
                scan_runs: [RUN_2, RUN_1],
                risk: { ...detail({}).risk!, ...RISK_OUT },
                validation: { ...detail({}).validation!, ...VALIDATION_OUT },
              })
            : riskDone
              ? detail({
                  project: PROJECT,
                  scan_runs: [RUN_2, RUN_1],
                  risk: { ...detail({}).risk!, ...RISK_OUT },
                  validation: null,
                })
              : detail({
                  project: PROJECT,
                  scan_runs: [RUN_2, RUN_1],
                  risk: null,
                  sla: null,
                  validation: null,
                });
          return { ok: true, status: 200, json: async () => current };
        }
        if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
          return {
            ok: false,
            status: 404,
            json: async () => ({ detail: "no approval request" }),
          };
        }
        if (method === "POST" && url === "/api/findings/f-sql-1/risk") {
          riskDone = true;
          return { ok: true, status: 200, json: async () => RISK_OUT };
        }
        if (method === "POST" && url === "/api/findings/f-sql-1/validate") {
          validateDone = true;
          return { ok: true, status: 200, json: async () => VALIDATION_OUT };
        }
        throw new Error(`unexpected request: ${method} ${url}`);
      },
    );
    vi.stubGlobal("fetch", fetchMock);
    renderPage();
    await loaded();
    const select = screen.getByLabelText("Scan run context");
    await user.selectOptions(select, RUN_2.scan_run_id);
    await user.click(
      within(panel("Risk")).getByRole("button", { name: "Assess Risk" }),
    );
    await within(panel("Risk")).findByRole("status");
    await user.click(
      within(panel("Validation")).getByRole("button", { name: "Validate" }),
    );
    await within(panel("Validation")).findByRole("status");
    const riskPost = onCall.mock.calls.find(
      ([url, requestInit]) =>
        String(url) === "/api/findings/f-sql-1/risk" &&
        (requestInit?.method ?? "").toUpperCase() === "POST",
    );
    const validatePost = onCall.mock.calls.find(
      ([url, requestInit]) =>
        String(url) === "/api/findings/f-sql-1/validate" &&
        (requestInit?.method ?? "").toUpperCase() === "POST",
    );
    expect(JSON.parse(String(riskPost?.[1]?.body))).toEqual({
      scan_run_id: RUN_2.scan_run_id,
    });
    expect(JSON.parse(String(validatePost?.[1]?.body))).toEqual({
      provider: "huggingface",
      scan_run_id: RUN_2.scan_run_id,
    });
  });
});

describe("finding risk assessment actions", () => {
  it("shows Assess Risk when no risk assessment exists", async () => {
    mockRiskFlow({ detail: detail({ risk: null, sla: null }) });
    renderPage();
    await loaded();
    expect(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    ).toBeInTheDocument();
    expect(
      within(riskSection()).getByText("Risk assessment not available"),
    ).toBeInTheDocument();
  });

  it("shows Risk Assessment Available when an assessment exists and no rerun button", async () => {
    mockRiskFlow({ detail: detail({}) });
    renderPage();
    await loaded();
    expect(
      within(riskSection()).getByText("Risk Assessment Available"),
    ).toBeInTheDocument();
    expect(
      within(riskSection()).queryByRole("button", { name: "Assess Risk" }),
    ).not.toBeInTheDocument();
  });

  it("sends POST /api/findings/f-sql-1/risk with no request body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    );
    await within(riskSection()).findByRole("status");
    const riskPost = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/risk" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(riskPost).toBeDefined();
    expect(riskPost?.[1]?.body).toBeUndefined();
  });

  it("shows Assessing Risk and disables the button while pending", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      delayMs: 80,
    });
    renderPage();
    await loaded();
    const button = within(riskSection()).getByRole("button", {
      name: "Assess Risk",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Assessing Risk\u2026");
    await within(riskSection()).findByRole("status");
    expect(button).not.toBeInTheDocument();
  });

  it("sends only one risk request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(riskSection()).getByRole("button", {
      name: "Assess Risk",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    await user.click(button);
    const riskPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/risk" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(riskPosts).toHaveLength(1);
    await within(riskSection()).findByRole("status");
  });

  it("displays the real backend risk values after assessment", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
    });
    renderPage();
    await loaded();
    await user.click(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    );
    const status = await within(riskSection()).findByRole("status");
    expect(status).toHaveTextContent("Risk Assessment Available");
    const section = riskSection();
    expect(within(section).getByText("88")).toBeInTheDocument();
    expect(within(section).getByText("P1")).toBeInTheDocument();
    expect(within(section).getByText("severity")).toBeInTheDocument();
    expect(within(section).getByText("75 pts")).toBeInTheDocument();
    expect(
      within(section).getByText("base severity weight (HIGH = 75)"),
    ).toBeInTheDocument();
  });

  it("surfaces a 404 safely and allows retry", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      riskResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({ detail: "finding not found: f-sql-1" }),
        },
      ],
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(riskSection()).getByRole("button", {
      name: "Assess Risk",
    });
    await user.click(button);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to assess risk: finding not found: f-sql-1",
    );
    expect(button).toBeEnabled();
    await user.click(button);
    await within(riskSection()).findByRole("status");
    const riskPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/risk" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(riskPosts).toHaveLength(2);
  });

  it("surfaces a 500 safely without stack traces", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      riskResponses: [
        {
          ok: false,
          status: 500,
          json: async () => ({ detail: "risk service unavailable" }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(riskSection()).getByRole("button", { name: "Assess Risk" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to assess risk: risk service unavailable",
    );
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("finding SLA actions", () => {
  function slaSection() {
    return panel("SLA");
  }

  it("shows Start SLA only when a risk assessment exists", async () => {
    mockRiskFlow({ detail: detail({ risk: null, sla: null }) });
    renderPage();
    await loaded();
    expect(
      within(slaSection()).queryByRole("button", { name: "Start SLA" }),
    ).not.toBeInTheDocument();
    expect(
      within(slaSection()).getByText("Assess risk before starting an SLA."),
    ).toBeInTheDocument();
  });

  it("never calls the SLA endpoint before risk exists", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      riskResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({ detail: "finding not found: f-sql-1" }),
        },
      ],
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Risk")).getByRole("button", { name: "Assess Risk" }),
    );
    await screen.findByRole("alert");
    for (const [url] of onCall.mock.calls) {
      expect(String(url)).not.toContain("/sla");
    }
  });

  it("sends POST /api/findings/f-sql-1/sla with no request body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      afterStartSla: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "active",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: null,
          resolved_at: null,
          escalation_level: 0,
          remaining_seconds: 7200,
        },
      }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Risk")).getByRole("button", { name: "Assess Risk" }),
    );
    await within(riskSection()).findByRole("status");
    await user.click(
      within(slaSection()).getByRole("button", { name: "Start SLA" }),
    );
    await waitFor(() => {
      expect(screen.getByText("Active")).toBeInTheDocument();
    });
    const slaPost = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/sla" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(slaPost).toBeDefined();
    expect(slaPost?.[1]?.body).toBeUndefined();
  });

  it("shows Starting SLA and prevents duplicate SLA requests", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      afterStartSla: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "active",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: null,
          resolved_at: null,
          escalation_level: 0,
          remaining_seconds: 7200,
        },
      }),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(slaSection()).getByRole("button", {
      name: "Start SLA",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Starting SLA\u2026");
    await user.click(button);
    const slaPosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/sla" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(slaPosts).toHaveLength(1);
    await waitFor(() => {
      expect(screen.getByText("Active")).toBeInTheDocument();
    });
  });

  it("displays the real SLA values with a static remaining snapshot", async () => {
    mockRiskFlow({
      detail: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "active",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: null,
          resolved_at: null,
          escalation_level: 0,
          remaining_seconds: 7200,
        },
      }),
    });
    renderPage();
    await loaded();
    const section = slaSection();
    expect(within(section).getByText("Active")).toBeInTheDocument();
    expect(within(section).getByText("P1")).toBeInTheDocument();
    expect(within(section).getByText("2h remaining")).toBeInTheDocument();
    expect(
      within(section).getByText("2026-08-16 10:00:00 UTC"),
    ).toBeInTheDocument();
    expect(
      within(section).getByText("2026-08-17 10:00:00 UTC"),
    ).toBeInTheDocument();
  });

  it("shows the breached state after an SLA check", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "active",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: null,
          resolved_at: null,
          escalation_level: 0,
          remaining_seconds: 7200,
        },
      }),
      afterCheckSla: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "breached",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: "2026-08-16T12:00:00Z",
          resolved_at: null,
          escalation_level: 1,
          remaining_seconds: null,
        },
      }),
    });
    renderPage();
    await loaded();
    await user.click(
      within(slaSection()).getByRole("button", { name: "Check SLA" }),
    );
    await waitFor(() => {
      expect(screen.getByText("SLA BREACHED")).toBeInTheDocument();
    });
    expect(screen.getByText("Level 1")).toBeInTheDocument();
  });

  it("surfaces an SLA check error safely", async () => {
    const user = userEvent.setup();
    mockRiskFlow({
      detail: detail({}),
      checkResponses: [
        {
          ok: false,
          status: 500,
          json: async () => ({ detail: "sla check failed" }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(slaSection()).getByRole("button", { name: "Check SLA" }),
    );
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Unable to check SLA: sla check failed");
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("finding risk and SLA workflow safety", () => {
  it("triggers no other pipeline stage during risk and SLA actions", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRiskFlow({
      detail: detail({ risk: null, sla: null }),
      afterAssess: detail({ risk: { ...detail({}).risk!, ...RISK_OUT }, sla: null }),
      afterStartSla: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "active",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: null,
          resolved_at: null,
          escalation_level: 0,
          remaining_seconds: 7200,
        },
      }),
      afterCheckSla: detail({
        risk: { ...detail({}).risk!, ...RISK_OUT },
        sla: {
          status: "breached",
          priority: "P1",
          started_at: "2026-08-16T10:00:00Z",
          due_at: "2026-08-17T10:00:00Z",
          breached_at: "2026-08-16T12:00:00Z",
          resolved_at: null,
          escalation_level: 1,
          remaining_seconds: null,
        },
      }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Risk")).getByRole("button", { name: "Assess Risk" }),
    );
    await within(riskSection()).findByRole("status");
    await user.click(
      within(panel("SLA")).getByRole("button", { name: "Start SLA" }),
    );
    await waitFor(() => {
      expect(screen.getByText("Active")).toBeInTheDocument();
    });
    await user.click(
      within(panel("SLA")).getByRole("button", { name: "Check SLA" }),
    );
    await waitFor(() => {
      expect(screen.getByText("SLA BREACHED")).toBeInTheDocument();
    });
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/findings/f-sql-1") ||
        (method === "GET" && path === "/api/findings/f-sql-1/approval") ||
        (method === "GET" && path === "/api/findings/f-sql-1/remediation") ||
        (method === "GET" && path === "/api/approvals/ap-1/history") ||
        (method === "POST" && path === "/api/findings/f-sql-1/risk") ||
        (method === "POST" && path === "/api/findings/f-sql-1/sla") ||
        (method === "POST" && path === "/api/findings/f-sql-1/sla/check");
      expect(allowed).toBe(true);
    }
    for (const [url, init] of onCall.mock.calls) {
      const path = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method !== "POST") continue;
      for (const stage of [
        "/deduplicate",
        "/validate",
        "/prove",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("contains no countdown logic, no fake deadlines and no shell/fs access", async () => {
    const apiSource = readFileSync("src/api/risk.ts", "utf-8");
    const hookSource = readFileSync("src/hooks/useRiskActions.ts", "utf-8");
    const riskPanelSource = readFileSync(
      "src/components/finding-detail/RiskPanel.tsx",
      "utf-8",
    );
    const slaPanelSource = readFileSync(
      "src/components/finding-detail/SlaPanel.tsx",
      "utf-8",
    );
    const source =
      apiSource + "\n" + hookSource + "\n" + riskPanelSource + "\n" + slaPanelSource;
    expect(source).not.toContain("setInterval");
    expect(source).not.toContain("countdown");
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

describe("finding validation actions", () => {
  function validationSection() {
    return panel("Validation");
  }

  it("shows Validate when no validation exists", async () => {
    mockValidateFlow({ detail: detail({ validation: null }) });
    renderPage();
    await loaded();
    expect(
      within(validationSection()).getByRole("button", { name: "Validate" }),
    ).toBeInTheDocument();
    expect(
      within(validationSection()).getByText("Not validated"),
    ).toBeInTheDocument();
  });

  it("shows Validation Available when validated and no rerun button", async () => {
    mockValidateFlow({ detail: detail({}) });
    renderPage();
    await loaded();
    expect(
      within(validationSection()).getByText("Validation Available"),
    ).toBeInTheDocument();
    expect(
      within(validationSection()).queryByRole("button", { name: "Validate" }),
    ).not.toBeInTheDocument();
  });

  it("sends POST /api/findings/f-sql-1/validate with the huggingface provider", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(validationSection()).getByRole("button", { name: "Validate" }),
    );
    await within(validationSection()).findByRole("status");
    const validatePost = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/validate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(validatePost).toBeDefined();
    expect(validatePost?.[1]?.headers).toEqual({
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(validatePost?.[1]?.body))).toEqual({
      provider: "huggingface",
    });
  });

  it("shows Validating and disables the button while pending", async () => {
    const user = userEvent.setup();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
      delayMs: 80,
    });
    renderPage();
    await loaded();
    const button = within(validationSection()).getByRole("button", {
      name: "Validate",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Validating\u2026");
    await within(validationSection()).findByRole("status");
    expect(button).not.toBeInTheDocument();
  });

  it("sends only one validation request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(validationSection()).getByRole("button", {
      name: "Validate",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    await user.click(button);
    const validatePosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/validate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(validatePosts).toHaveLength(1);
    await within(validationSection()).findByRole("status");
  });

  it("displays the real backend verdict values after validation", async () => {
    const user = userEvent.setup();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
    });
    renderPage();
    await loaded();
    await user.click(
      within(validationSection()).getByRole("button", { name: "Validate" }),
    );
    const status = await within(validationSection()).findByRole("status");
    expect(status).toHaveTextContent("Validation Available");
    const section = validationSection();
    expect(within(section).getByText("TRUE POSITIVE")).toBeInTheDocument();
    expect(within(section).getByText("91%")).toBeInTheDocument();
    expect(
      within(section).getByText(/The taint path from request\.args reaches/),
    ).toBeInTheDocument();
    expect(
      within(section).getByText("sanitizer_observations"),
    ).toBeInTheDocument();
  });

  it("surfaces a 404 safely and allows retry", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
      validateResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({ detail: "finding not found: f-sql-1" }),
        },
      ],
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(validationSection()).getByRole("button", {
      name: "Validate",
    });
    await user.click(button);
    const alert = await within(validationSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to validate: finding not found: f-sql-1",
    );
    expect(button).toBeEnabled();
    await user.click(button);
    await within(validationSection()).findByRole("status");
    const validatePosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/validate" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(validatePosts).toHaveLength(2);
  });

  it("surfaces the LLM configuration error (503) safely", async () => {
    const user = userEvent.setup();
    mockValidateFlow({
      detail: detail({ validation: null }),
      validateResponses: [
        {
          ok: false,
          status: 503,
          json: async () => ({
            detail:
              "LLM is not configured: set LLM_MODEL to the Hugging Face model id (e.g. a model hosted on or routed through the Inference API)",
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(validationSection()).getByRole("button", { name: "Validate" }),
    );
    const alert = await within(validationSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to validate: LLM is not configured: set LLM_MODEL to the Hugging Face model id (e.g. a model hosted on or routed through the Inference API)",
    );
    expect(alert.textContent).not.toContain("Traceback");
  });

  it("surfaces a 500 safely without stack traces", async () => {
    const user = userEvent.setup();
    mockValidateFlow({
      detail: detail({ validation: null }),
      validateResponses: [
        {
          ok: false,
          status: 500,
          json: async () => ({ detail: "validation service unavailable" }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(validationSection()).getByRole("button", { name: "Validate" }),
    );
    const alert = await within(validationSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to validate: validation service unavailable",
    );
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("finding validation workflow safety", () => {
  it("triggers no other pipeline stage during validation", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ validation: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT } }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Validation")).getByRole("button", { name: "Validate" }),
    );
    await within(panel("Validation")).findByRole("status");
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/findings/f-sql-1") ||
        (method === "GET" && path === "/api/findings/f-sql-1/approval") ||
        (method === "GET" && path === "/api/findings/f-sql-1/remediation") ||
        (method === "GET" && path === "/api/approvals/ap-1/history") ||
        (method === "POST" && path === "/api/findings/f-sql-1/validate");
      expect(allowed).toBe(true);
    }
    for (const [url, init] of onCall.mock.calls) {
      const path = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method !== "POST") continue;
      for (const stage of [
        "/risk",
        "/sla",
        "/deduplicate",
        "/prove",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("contains no local verdict logic and no shell/fs access", async () => {
    const apiSource = readFileSync("src/api/findingValidate.ts", "utf-8");
    const hookSource = readFileSync("src/hooks/useValidateFinding.ts", "utf-8");
    const panelSource = readFileSync(
      "src/components/finding-detail/ValidationPanel.tsx",
      "utf-8",
    );
    const source = apiSource + "\n" + hookSource + "\n" + panelSource;
    expect(source).not.toContain("setInterval");
    expect(source).not.toContain("countdown");
    expect(source).not.toContain("Math.random");
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

describe("finding proof actions", () => {
  it("shows Prove Finding when the verdict is true_positive and no proof exists", async () => {
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
    });
    renderPage();
    await loaded();
    expect(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    ).toBeInTheDocument();
    expect(
      within(proofSection()).getByText("No proof result"),
    ).toBeInTheDocument();
  });

  it("does not show Prove Finding when validation is missing", async () => {
    mockProveFlow({ detail: detail({ validation: null, proof: null }) });
    renderPage();
    await loaded();
    expect(
      within(proofSection()).queryByRole("button", { name: "Prove Finding" }),
    ).not.toBeInTheDocument();
    expect(
      within(proofSection()).getByText(
        "Proof requires a validation result. Validate the finding before proving.",
      ),
    ).toBeInTheDocument();
  });

  it("shows the backend verdict gate for FALSE POSITIVE without a Prove button", async () => {
    mockProveFlow({
      detail: detail({
        validation: {
          ...detail({}).validation!,
          verdict: "false_positive",
        } as FindingDetail["validation"],
        proof: null,
      }),
    });
    renderPage();
    await loaded();
    expect(
      within(proofSection()).queryByRole("button", { name: "Prove Finding" }),
    ).not.toBeInTheDocument();
    expect(
      within(proofSection()).getByText(
        "Finding is not eligible for proof: verdict=false_positive",
      ),
    ).toBeInTheDocument();
  });

  it("shows the backend verdict gate for UNCERTAIN without a Prove button", async () => {
    mockProveFlow({
      detail: detail({
        validation: {
          ...detail({}).validation!,
          verdict: "uncertain",
        } as FindingDetail["validation"],
        proof: null,
      }),
    });
    renderPage();
    await loaded();
    expect(
      within(proofSection()).queryByRole("button", { name: "Prove Finding" }),
    ).not.toBeInTheDocument();
    expect(
      within(proofSection()).getByText(
        "Finding is not eligible for proof: verdict=uncertain",
      ),
    ).toBeInTheDocument();
  });

  it("does not show Prove Finding when a proof already exists", async () => {
    mockProveFlow({ detail: detail({}) });
    renderPage();
    await loaded();
    expect(
      within(proofSection()).queryByRole("button", { name: "Prove Finding" }),
    ).not.toBeInTheDocument();
    expect(
      within(proofSection()).getByText("Proof Result Available"),
    ).toBeInTheDocument();
    expect(within(proofSection()).getByText("VERIFIED")).toBeInTheDocument();
  });

  it("sends POST /api/findings/f-sql-1/prove with no request body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    await within(proofSection()).findByRole("status");
    const provePost = onCall.mock.calls.find(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/prove" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(provePost).toBeDefined();
    expect(provePost?.[1]?.body).toBeUndefined();
  });

  it("shows Proving and disables the button while pending", async () => {
    const user = userEvent.setup();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      delayMs: 80,
    });
    renderPage();
    await loaded();
    const button = within(proofSection()).getByRole("button", {
      name: "Prove Finding",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveTextContent("Proving\u2026");
    await within(proofSection()).findByRole("status");
    expect(button).not.toBeInTheDocument();
  });

  it("sends only one prove request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(proofSection()).getByRole("button", {
      name: "Prove Finding",
    });
    await user.click(button);
    await waitFor(() => expect(button).toBeDisabled());
    await user.click(button);
    const provePosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/prove" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(provePosts).toHaveLength(1);
    await within(proofSection()).findByRole("status");
  });

  it("refreshes the finding detail after a successful proof", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      onCall,
    });
    renderPage();
    await loaded();
    const getCallsBefore = onCall.mock.calls.filter(
      ([url]) => String(url) === "/api/findings/f-sql-1",
    ).length;
    expect(getCallsBefore).toBe(2);
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    await within(proofSection()).findByRole("status");
    const getCallsAfter = onCall.mock.calls.filter(
      ([url]) => String(url) === "/api/findings/f-sql-1",
    ).length;
    expect(getCallsAfter).toBe(3);
    expect(within(proofSection()).getByText("VERIFIED")).toBeInTheDocument();
  });

  it("displays the VERIFIED result with confidence, summary, duration and created time", async () => {
    mockProveFlow({
      detail: proveFixture({
        status: "verified",
        confidence: 0.94,
        summary:
          "unsafe string construction returned 2 rows while the parameterized construction returned 0 rows for the same benign marker in the local fixture",
        duration_ms: 4567,
        created_at: "2026-08-16T11:00:00Z",
        error: null,
        sandbox_policy: {
          network_enabled: false,
          allow_loopback: false,
          allowed_paths: [],
          timeout_seconds: 10,
          max_output_bytes: 16384,
          max_processes: 1,
          temporary_directory: "",
        },
      }),
    });
    renderPage();
    await loaded();
    const section = proofSection();
    expect(within(section).getByText("VERIFIED")).toBeInTheDocument();
    expect(within(section).getByText("94%")).toBeInTheDocument();
    expect(
      within(section).getByText(
        "unsafe string construction returned 2 rows while the parameterized construction returned 0 rows for the same benign marker in the local fixture",
      ),
    ).toBeInTheDocument();
    expect(within(section).getByText("4.57s")).toBeInTheDocument();
    expect(
      within(section).getByText("2026-08-16 11:00:00 UTC"),
    ).toBeInTheDocument();
    expect(within(section).getByText("16 KiB")).toBeInTheDocument();
    expect(within(section).getByText("10s")).toBeInTheDocument();
    expect(within(section).getByText("1")).toBeInTheDocument();
    expect(within(section).getAllByText("No").length).toBeGreaterThanOrEqual(2);
  });

  it("displays the NOT VERIFIED result", async () => {
    mockProveFlow({
      detail: proveFixture({
        status: "not_verified",
        summary: "unsafe and safe constructions behaved identically",
      }),
    });
    renderPage();
    await loaded();
    const section = proofSection();
    expect(within(section).getByText("NOT VERIFIED")).toBeInTheDocument();
    expect(
      within(section).getByText("unsafe and safe constructions behaved identically"),
    ).toBeInTheDocument();
  });

  it("displays the BLOCKED result", async () => {
    mockProveFlow({
      detail: proveFixture({
        status: "blocked",
        summary: "restrictions that cannot be guaranteed",
      }),
    });
    renderPage();
    await loaded();
    const section = proofSection();
    expect(within(section).getByText("BLOCKED")).toBeInTheDocument();
  });

  it("displays the ERROR result with the backend error message", async () => {
    mockProveFlow({
      detail: proveFixture({
        status: "error",
        summary: "proof harness could not be executed",
        error: "proof harness failed (rc=1): boom",
      }),
    });
    renderPage();
    await loaded();
    const section = proofSection();
    expect(within(section).getByText("ERROR")).toBeInTheDocument();
    expect(
      within(section).getByText("proof harness failed (rc=1): boom"),
    ).toBeInTheDocument();
  });

  it("surfaces a 404 safely and allows retry", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      proveResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({ detail: "finding not found: f-sql-1" }),
        },
      ],
      onCall,
    });
    renderPage();
    await loaded();
    const button = within(proofSection()).getByRole("button", {
      name: "Prove Finding",
    });
    await user.click(button);
    const alert = await within(proofSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to prove finding: finding not found: f-sql-1",
    );
    expect(button).toBeEnabled();
    await user.click(button);
    await within(proofSection()).findByRole("status");
    const provePosts = onCall.mock.calls.filter(
      ([url, init]) =>
        String(url) === "/api/findings/f-sql-1/prove" &&
        (init?.method ?? "").toUpperCase() === "POST",
    );
    expect(provePosts).toHaveLength(2);
  });

  it("surfaces the missing-validation 404 detail safely", async () => {
    const user = userEvent.setup();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      proveResponses: [
        {
          ok: false,
          status: 404,
          json: async () => ({
            detail: "validation result missing: f-sql-1",
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    const alert = await within(proofSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to prove finding: validation result missing: f-sql-1",
    );
  });

  it("surfaces a 409 gate as a specific policy error, not a generic failure", async () => {
    const user = userEvent.setup();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      proveResponses: [
        {
          ok: false,
          status: 409,
          json: async () => ({
            detail: "finding is not eligible for proof: verdict=false_positive",
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    const alert = await within(proofSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to prove finding: finding is not eligible for proof: verdict=false_positive",
    );
    expect(alert.textContent).not.toContain("request failed");
  });

  it("surfaces a 500 safely without stack traces", async () => {
    const user = userEvent.setup();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      proveResponses: [
        {
          ok: false,
          status: 500,
          json: async () => ({ detail: "proof service unavailable" }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    const alert = await within(proofSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to prove finding: proof service unavailable",
    );
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("finding proof workflow safety", () => {
  it("only triggers proof by explicit user action, never on page load", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      onCall,
    });
    renderPage();
    await loaded();
    const posts = onCall.mock.calls.filter(
      ([, init]) => (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(posts).toHaveLength(0);
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    await within(proofSection()).findByRole("status");
    expect(
      onCall.mock.calls.filter(
        ([url, init]) =>
          String(url) === "/api/findings/f-sql-1/prove" &&
          (init?.method ?? "").toUpperCase() === "POST",
      ),
    ).toHaveLength(1);
  });

  it("successful validation does not automatically trigger proof", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockValidateFlow({
      detail: detail({ validation: null, proof: null }),
      afterValidate: detail({ validation: { ...VALIDATION_OUT }, proof: null }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(panel("Validation")).getByRole("button", { name: "Validate" }),
    );
    await within(panel("Validation")).findByRole("status");
    expect(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    ).toBeInTheDocument();
    for (const [url] of onCall.mock.calls) {
      expect(String(url)).not.toContain("/prove");
    }
  });

  it("triggers no other pipeline stage during proof", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null }),
      afterProve: proveFixture({}),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    await within(proofSection()).findByRole("status");
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/findings/f-sql-1") ||
        (method === "GET" && path === "/api/findings/f-sql-1/approval") ||
        (method === "GET" && path === "/api/findings/f-sql-1/remediation") ||
        (method === "GET" && path === "/api/approvals/ap-1/history") ||
        (method === "POST" && path === "/api/findings/f-sql-1/prove");
      expect(allowed).toBe(true);
    }
    for (const [url, init] of onCall.mock.calls) {
      const path = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method !== "POST") continue;
      for (const stage of [
        "/risk",
        "/sla",
        "/validate",
        "/deduplicate",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("contains no sandbox, subprocess, payload or filesystem logic", async () => {
    const apiSource = readFileSync("src/api/proofAction.ts", "utf-8");
    const hookSource = readFileSync("src/hooks/useProveFinding.ts", "utf-8");
    const panelSource = readFileSync(
      "src/components/finding-detail/ProofPanel.tsx",
      "utf-8",
    );
    const source = apiSource + "\n" + hookSource + "\n" + panelSource;
    expect(source).not.toContain("setInterval");
    expect(source).not.toContain("countdown");
    expect(source).not.toContain("Math.random");
    for (const forbidden of [
      "child_process",
      "spawn",
      "exec(",
      "execSync",
      "node:fs",
      'require("fs")',
      "shell",
      "git clone",
      "eval",
      "Function(",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });

  it("does not render dangerous proof internals or sandbox locations", async () => {
    const dangerous = {
      ...detail({}),
      validation: detail({}).validation,
      proof: {
        ...detail({}).proof!,
        artifacts: [
          {
            name: "payload",
            kind: "sql_statement",
            content: "SELECT 'pwned'; DROP TABLE users;",
          },
        ],
        evidence: [
          {
            name: "input_value",
            kind: "observation",
            content: "rm -rf /tmp/evil",
          },
        ],
        error: null,
        sandbox_policy: {
          network_enabled: false,
          allow_loopback: false,
          allowed_paths: ["/etc/passwd"],
          timeout_seconds: 10,
          max_output_bytes: 16384,
          max_processes: 1,
          temporary_directory: "/tmp/sandbox-secret",
        },
      },
    } as FindingDetail;
    mockProveFlow({ detail: dangerous });
    renderPage();
    await loaded();
    const section = proofSection();
    expect(within(section).queryByText(/DROP TABLE users/)).not.toBeInTheDocument();
    expect(within(section).queryByText("rm -rf /tmp/evil")).not.toBeInTheDocument();
    expect(within(section).queryByText("/etc/passwd")).not.toBeInTheDocument();
    expect(within(section).queryByText("/tmp/sandbox-secret")).not.toBeInTheDocument();
    expect(within(section).queryByText("secret")).not.toBeInTheDocument();
    expect(document.querySelectorAll("script, iframe, object").length).toBe(0);
  });
});

const APPROVAL_CREATED: ApprovalRequest = {
  id: "ap-9",
  finding_id: "f-sql-1",
  status: "pending",
  requested_at: "2026-08-16T12:00:00Z",
  requested_by: "system",
  reviewed_at: null,
  reviewed_by: null,
  reason: null,
  action: "remediation",
  version: 1,
};

const APPROVAL_APPROVED: ApprovalRequest = {
  ...APPROVAL_CREATED,
  status: "approved",
  reviewed_at: "2026-08-16T12:30:00Z",
  reviewed_by: "security-analyst",
  reason: "Verified and proof reviewed.",
};

const APPROVAL_REJECTED: ApprovalRequest = {
  ...APPROVAL_CREATED,
  status: "rejected",
  reviewed_at: "2026-08-16T12:30:00Z",
  reviewed_by: "security-analyst",
  reason: "Risk accepted.",
};

const APPROVAL_CHANGES: ApprovalRequest = {
  ...APPROVAL_CREATED,
  status: "changes_requested",
  reviewed_at: "2026-08-16T12:30:00Z",
  reviewed_by: "security-analyst",
  reason: "Need additional evidence.",
};

const APPROVAL_RESUBMITTED: ApprovalRequest = {
  ...APPROVAL_CREATED,
  status: "pending",
  version: 2,
  reviewed_at: "2026-08-16T12:45:00Z",
  reviewed_by: "security-analyst",
  reason: "Evidence added.",
};

function approvalFlowEvents(
  flags: { changed: boolean; resubmitted: boolean; approved: boolean; rejected: boolean },
): ApprovalEvent[] {
  const events: ApprovalEvent[] = [
    {
      id: "ev-1",
      approval_id: "ap-9",
      finding_id: "f-sql-1",
      previous_status: null,
      new_status: "pending",
      actor: "system",
      reason: null,
      created_at: "2026-08-16T12:00:00Z",
    },
  ];
  if (flags.changed) {
    events.push({
      id: "ev-2",
      approval_id: "ap-9",
      finding_id: "f-sql-1",
      previous_status: "pending",
      new_status: "changes_requested",
      actor: "security-analyst",
      reason: "Need additional evidence.",
      created_at: "2026-08-16T12:30:00Z",
    });
  }
  if (flags.resubmitted) {
    events.push({
      id: "ev-3",
      approval_id: "ap-9",
      finding_id: "f-sql-1",
      previous_status: "changes_requested",
      new_status: "pending",
      actor: "security-analyst",
      reason: "Evidence added.",
      created_at: "2026-08-16T12:45:00Z",
    });
  }
  if (flags.approved) {
    events.push({
      id: "ev-4",
      approval_id: "ap-9",
      finding_id: "f-sql-1",
      previous_status: "pending",
      new_status: "approved",
      actor: "security-analyst",
      reason: "Verified and proof reviewed.",
      created_at: "2026-08-16T12:30:00Z",
    });
  }
  if (flags.rejected) {
    events.push({
      id: "ev-5",
      approval_id: "ap-9",
      finding_id: "f-sql-1",
      previous_status: "pending",
      new_status: "rejected",
      actor: "security-analyst",
      reason: "Risk accepted.",
      created_at: "2026-08-16T12:30:00Z",
    });
  }
  return events;
}

function mockApprovalFlow(options: {
  detail: FindingDetail;
  afterCreate?: FindingDetail;
  afterApprove?: FindingDetail;
  afterReject?: FindingDetail;
  afterChanges?: FindingDetail;
  afterResubmit?: FindingDetail;
  createResponses?: MockResponse[];
  approveResponses?: MockResponse[];
  rejectResponses?: MockResponse[];
  changesResponses?: MockResponse[];
  resubmitResponses?: MockResponse[];
  delayMs?: number;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let created = false;
  let approved = false;
  let rejected = false;
  let changed = false;
  let resubmitted = false;

  const currentDetail = () => {
    if (resubmitted && options.afterResubmit) return options.afterResubmit;
    if (approved && options.afterApprove) return options.afterApprove;
    if (rejected && options.afterReject) return options.afterReject;
    if (changed && options.afterChanges) return options.afterChanges;
    if (created && options.afterCreate) return options.afterCreate;
    return options.detail;
  };

  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      if (method === "GET" && url === "/api/findings/f-sql-1") {
        return { ok: true, status: 200, json: async () => currentDetail() };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
        const approval = (currentDetail() as FindingDetail).approval;
        if (approval) {
          return { ok: true, status: 200, json: async () => approval };
        }
        return {
          ok: false,
          status: 404,
          json: async () => ({ detail: "no approval request for finding: f-sql-1" }),
        };
      }
      if (method === "GET" && url === "/api/approvals/ap-9/history") {
        return {
          ok: true,
          status: 200,
          json: async () =>
            approvalFlowEvents({ changed, resubmitted, approved, rejected }),
        };
      }
      const consume = async (
        responses: MockResponse[] | undefined,
        success: () => Promise<unknown>,
      ): Promise<MockResponse> => {
        if (options.delayMs) {
          await new Promise((resolve) => setTimeout(resolve, options.delayMs));
        }
        if (responses && responses.length > 0) {
          return responses.shift() as MockResponse;
        }
        return { ok: true, status: 200, json: success };
      };
      if (method === "POST" && url === "/api/findings/f-sql-1/approval") {
        const response = await consume(options.createResponses, async () => APPROVAL_CREATED);
        if (response.ok) created = true;
        return response;
      }
      if (method === "POST" && url === "/api/approvals/ap-9/approve") {
        const response = await consume(options.approveResponses, async () => APPROVAL_APPROVED);
        if (response.ok) approved = true;
        return response;
      }
      if (method === "POST" && url === "/api/approvals/ap-9/reject") {
        const response = await consume(options.rejectResponses, async () => APPROVAL_REJECTED);
        if (response.ok) rejected = true;
        return response;
      }
      if (method === "POST" && url === "/api/approvals/ap-9/request-changes") {
        const response = await consume(options.changesResponses, async () => APPROVAL_CHANGES);
        if (response.ok) changed = true;
        return response;
      }
      if (method === "POST" && url === "/api/approvals/ap-9/resubmit") {
        const response = await consume(options.resubmitResponses, async () => APPROVAL_RESUBMITTED);
        if (response.ok) resubmitted = true;
        return response;
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function approvalSection() {
  return panel("Human Approval");
}

describe("finding approval request actions", () => {
  it("shows Request Approval when validation and proof qualify", async () => {
    mockApprovalFlow({ detail: detail({ approval: null }) });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(within(section).getByText("No approval request")).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Request Approval" }),
    ).toBeInTheDocument();
    expect(within(section).queryByText("Approval required")).not.toBeInTheDocument();
  });

  it("hides Request Approval when validation is missing", async () => {
    mockApprovalFlow({ detail: detail({ approval: null, validation: null }) });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByText(
        "Finding has not been validated; approval requires VALIDATE verdict true_positive.",
      ),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Approval" }),
    ).not.toBeInTheDocument();
  });

  it("shows the VALIDATE gate when the verdict is not true_positive", async () => {
    mockApprovalFlow({
      detail: detail({
        approval: null,
        validation: { ...detail({}).validation!, verdict: "false_positive" },
      }),
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByText(
        "Finding is not eligible for approval: VALIDATE verdict is false_positive (requires true_positive)",
      ),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Approval" }),
    ).not.toBeInTheDocument();
  });

  it("shows the PROVE gate when proof is missing", async () => {
    mockApprovalFlow({
      detail: detail({ approval: null, proof: null }),
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByText(
        "Finding has not been proven; approval requires PROVE status verified.",
      ),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Approval" }),
    ).not.toBeInTheDocument();
  });

  it("shows the PROVE gate when proof is not verified", async () => {
    mockApprovalFlow({
      detail: detail({
        approval: null,
        proof: { ...detail({}).proof!, status: "not_verified" },
      }),
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByText(
        "Finding is not eligible for approval: PROVE status is not_verified (requires verified)",
      ),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Approval" }),
    ).not.toBeInTheDocument();
  });

  it("does not show Request Approval when a terminal approval exists", async () => {
    mockApprovalFlow({ detail: detail({ approval: { ...APPROVAL_APPROVED } }) });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).queryByRole("button", { name: "Request Approval" }),
    ).not.toBeInTheDocument();
    expect(
      within(section).getByText("Approved \u2014 action authorized."),
    ).toBeInTheDocument();
  });

  it("requests approval via POST with the exact backend body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(approvalSection()).getByRole("button", { name: "Request Approval" }),
    );
    await within(approvalSection()).findByText("Pending");
    const createCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/findings/f-sql-1/approval" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(createCalls).toHaveLength(1);
    expect(createCalls[0][1]?.body).toBe(
      JSON.stringify({ action: "remediation", requested_by: "system" }),
    );
    const section = approvalSection();
    expect(within(section).getByText("Approval required")).toBeInTheDocument();
    expect(within(section).getByText("ap-9")).toBeInTheDocument();
    expect(within(section).getByText("1")).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Approve" }),
    ).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Reject" }),
    ).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Request Changes" }),
    ).toBeInTheDocument();
    const history = within(section).getByRole("list", {
      name: "Approval history",
    });
    expect(
      await within(history).findByText("Request created \u2192 Pending"),
    ).toBeInTheDocument();
  });

  it("shows Requesting Approval and disables the button while pending", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      delayMs: 80,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    const button = within(section).getByRole("button", {
      name: "Request Approval",
    });
    await user.click(button);
    expect(
      within(section).getByRole("button", { name: "Requesting Approval\u2026" }),
    ).toBeDisabled();
    await within(section).findByText("Approval required");
  });

  it("sends only one create request when clicked repeatedly", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    const button = within(section).getByRole("button", {
      name: "Request Approval",
    });
    await user.click(button);
    await user.click(within(section).getByRole("button", { name: "Requesting Approval\u2026" }));
    await within(section).findByText("Approval required");
    const createCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/findings/f-sql-1/approval" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(createCalls).toHaveLength(1);
  });

  it("does not automatically request approval on page load", async () => {
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      onCall,
    });
    renderPage();
    await loaded();
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      expect(method).toBe("GET");
      expect(String(url)).not.toContain("/approval");
    }
  });

  it("surfaces a 409 gate error from the backend safely", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      createResponses: [
        {
          ok: false,
          status: 409,
          json: async () => ({
            detail:
              "finding f-sql-1 is not eligible for approval: PROVE status is not_verified (requires verified)",
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    await user.click(
      within(approvalSection()).getByRole("button", { name: "Request Approval" }),
    );
    const alert = await within(approvalSection()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Unable to request approval: finding f-sql-1 is not eligible for approval: PROVE status is not_verified (requires verified)",
    );
    expect(alert.textContent).not.toContain("Traceback");
    expect(
      within(approvalSection()).getByRole("button", { name: "Request Approval" }),
    ).toBeInTheDocument();
  });

  it("surfaces a 404 create error and recovers on retry", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      createResponses: [
        { ok: false, status: 404, json: async () => ({ detail: "finding not found" }) },
      ],
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(
      within(section).getByRole("button", { name: "Request Approval" }),
    );
    const alert = await within(section).findByRole("alert");
    expect(alert).toHaveTextContent("Unable to request approval: finding not found");
    await user.click(within(section).getByRole("button", { name: "Request Approval" }));
    await within(section).findByText("Approval required");
  });

  it("does not automatically request approval after a successful proof", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockProveFlow({
      detail: detail({ validation: detail({}).validation, proof: null, approval: null }),
      afterProve: detail({
        validation: detail({}).validation,
        proof: { ...detail({}).proof!, status: "verified" },
        approval: null,
      }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(proofSection()).getByRole("button", { name: "Prove Finding" }),
    );
    await within(proofSection()).findByRole("status");
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      if (method === "POST") {
        expect(String(url)).not.toContain("/approval");
      }
    }
    expect(
      within(approvalSection()).getByRole("button", { name: "Request Approval" }),
    ).toBeInTheDocument();
  });
});

describe("finding approval decisions", () => {
  it("renders Approve, Reject and Request Changes for a pending request", async () => {
    mockDetail(detail({}));
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByRole("button", { name: "Approve" }),
    ).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Reject" }),
    ).toBeInTheDocument();
    expect(
      within(section).getByRole("button", { name: "Request Changes" }),
    ).toBeInTheDocument();
  });

  it("states the demo reviewer identity and no authentication in the decision modal", async () => {
    const user = userEvent.setup();
    mockDetail(detail({}));
    renderPage();
    await loaded();
    await user.click(
      within(approvalSection()).getByRole("button", { name: "Approve" }),
    );
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(
        /This decision is recorded under the demo reviewer identity/,
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("security-analyst")).toBeInTheDocument();
    expect(
      within(dialog).getByText(/Authentication is not currently enabled/),
    ).toBeInTheDocument();
  });

  it("approves via POST with the exact decision body and shows the terminal state", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      afterApprove: detail({ approval: { ...APPROVAL_APPROVED } }),
      onCall,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified and proof reviewed.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    await within(section).findByText("Approved \u2014 action authorized.");
    const approveCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/approvals/ap-9/approve" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(approveCalls).toHaveLength(1);
    expect(approveCalls[0][1]?.body).toBe(
      JSON.stringify({
        reviewed_by: "security-analyst",
        reason: "Verified and proof reviewed.",
      }),
    );
    expect(within(section).getAllByText("security-analyst").length).toBeGreaterThan(0);
    const history = within(section).getByRole("list", { name: "Approval history" });
    expect(
      await within(history).findByText("Pending \u2192 Approved"),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Approve" }),
    ).not.toBeInTheDocument();
  });

  it("prevents duplicate decision submissions", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      afterApprove: detail({ approval: { ...APPROVAL_APPROVED } }),
      delayMs: 80,
      onCall,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified and proof reviewed.");
    const confirm = within(dialog).getByRole("button", { name: "Approve" });
    await user.click(confirm);
    await user.click(within(dialog).getByRole("button", { name: "Saving\u2026" }));
    await within(section).findByText("Approved \u2014 action authorized.");
    const approveCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/approvals/ap-9/approve" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(approveCalls).toHaveLength(1);
  });

  it("rejects via POST with the exact decision body", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      afterReject: detail({ approval: { ...APPROVAL_REJECTED } }),
      onCall,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Reject" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Risk accepted.");
    await user.click(within(dialog).getByRole("button", { name: "Reject" }));
    await within(section).findByText("Rejected \u2014 no further action.");
    const rejectCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/approvals/ap-9/reject" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(rejectCalls).toHaveLength(1);
    expect(rejectCalls[0][1]?.body).toBe(
      JSON.stringify({ reviewed_by: "security-analyst", reason: "Risk accepted." }),
    );
    const history = within(section).getByRole("list", { name: "Approval history" });
    expect(within(history).getByText("Pending \u2192 Rejected")).toBeInTheDocument();
  });

  it("requests changes and switches to the resubmit state", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      afterChanges: detail({ approval: { ...APPROVAL_CHANGES } }),
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(
      within(section).getByRole("button", { name: "Request Changes" }),
    );
    const dialog = screen.getByRole("dialog");
    await user.type(
      within(dialog).getByLabelText("Reason"),
      "Need additional evidence.",
    );
    await user.click(within(dialog).getByRole("button", { name: "Request Changes" }));
    await within(section).findByText("Changes Requested");
    expect(
      within(section).getByRole("button", { name: "Resubmit for Review" }),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Approve" }),
    ).not.toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Reject" }),
    ).not.toBeInTheDocument();
    const history = within(section).getByRole("list", { name: "Approval history" });
    expect(
      within(history).getByText("Pending \u2192 Changes Requested"),
    ).toBeInTheDocument();
  });

  it("resubmits and displays the backend-issued review cycle", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CHANGES } }),
      afterResubmit: detail({ approval: { ...APPROVAL_RESUBMITTED } }),
      onCall,
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(within(section).getByText("1")).toBeInTheDocument();
    await user.click(
      within(section).getByRole("button", { name: "Resubmit for Review" }),
    );
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Evidence added.");
    await user.click(within(dialog).getByRole("button", { name: "Resubmit" }));
    await within(section).findByText("Approval required");
    expect(within(section).getByText("2")).toBeInTheDocument();
    const resubmitCalls = onCall.mock.calls.filter(
      ([url, init]) =>
        url === "/api/approvals/ap-9/resubmit" &&
        (init?.method ?? "GET").toUpperCase() === "POST",
    );
    expect(resubmitCalls).toHaveLength(1);
    expect(resubmitCalls[0][1]?.body).toBe(
      JSON.stringify({ reviewed_by: "security-analyst", reason: "Evidence added." }),
    );
    const history = within(section).getByRole("list", { name: "Approval history" });
    expect(
      await within(history).findByText("Changes Requested \u2192 Pending"),
    ).toBeInTheDocument();
  });

  it("shows terminal states with no action buttons", async () => {
    mockApprovalFlow({ detail: detail({ approval: { ...APPROVAL_APPROVED } }) });
    const first = renderPage();
    await loaded();
    let section = approvalSection();
    expect(
      within(section).getByText("Approved \u2014 action authorized."),
    ).toBeInTheDocument();
    expect(within(section).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(within(section).queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Changes" }),
    ).not.toBeInTheDocument();
    first.unmount();

    mockApprovalFlow({ detail: detail({ approval: { ...APPROVAL_REJECTED } }) });
    renderPage();
    await loaded();
    section = approvalSection();
    expect(
      within(section).getByText("Rejected \u2014 no further action."),
    ).toBeInTheDocument();
    expect(within(section).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(within(section).queryByRole("button", { name: "Reject" })).not.toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Request Changes" }),
    ).not.toBeInTheDocument();
  });

  it("surfaces a 409 invalid-transition error in the modal", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      approveResponses: [
        {
          ok: false,
          status: 409,
          json: async () => ({
            detail: "invalid approval transition: approved -> approved is not allowed",
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent(
      "invalid approval transition: approved -> approved is not allowed",
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces a 422 validation error safely", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      approveResponses: [
        {
          ok: false,
          status: 422,
          json: async () => ({
            detail: [
              {
                loc: ["body", "reviewed_by"],
                msg: "field required",
                type: "value_error.missing",
              },
            ],
          }),
        },
      ],
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("reviewed_by: field required");
    expect(alert.textContent).not.toContain("Traceback");
  });

  it("surfaces a 500 safely without stack traces", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: { ...APPROVAL_CREATED } }),
      approveResponses: [
        { ok: false, status: 500, json: async () => ({ detail: "internal server error" }) },
      ],
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("internal server error");
    expect(alert.textContent).not.toContain("Traceback");
  });
});

describe("finding approval workflow safety", () => {
  it("triggers no other pipeline stage during the approval workflow", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      afterApprove: detail({ approval: { ...APPROVAL_APPROVED } }),
      onCall,
    });
    renderPage();
    await loaded();
    await user.click(
      within(approvalSection()).getByRole("button", { name: "Request Approval" }),
    );
    await within(approvalSection()).findByText("Pending");
    await user.click(
      within(approvalSection()).getByRole("button", { name: "Approve" }),
    );
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified and proof reviewed.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    await within(approvalSection()).findByText("Approved \u2014 action authorized.");
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/findings/f-sql-1") ||
        (method === "GET" && path === "/api/findings/f-sql-1/approval") ||
        (method === "GET" && path === "/api/findings/f-sql-1/remediation") ||
        (method === "GET" && path === "/api/approvals/ap-9/history") ||
        (method === "POST" && path === "/api/findings/f-sql-1/approval") ||
        (method === "POST" && path === "/api/approvals/ap-9/approve");
      expect(allowed).toBe(true);
    }
    for (const [url, init] of onCall.mock.calls) {
      const path = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method !== "POST") continue;
      for (const stage of [
        "/scan",
        "/deduplicate",
        "/validate",
        "/prove",
        "/risk",
        "/sla",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });

  it("contains no remediation, execution or filesystem logic", async () => {
    const apiSource = readFileSync("src/api/approvals.ts", "utf-8");
    const hookSource = readFileSync("src/hooks/useApprovalRequest.ts", "utf-8");
    const panelSource = readFileSync(
      "src/components/finding-detail/ApprovalPanel.tsx",
      "utf-8",
    );
    const source = apiSource + "\n" + hookSource + "\n" + panelSource;
    expect(source).not.toContain("setInterval");
    expect(source).not.toContain("countdown");
    expect(source).not.toContain("Math.random");
    for (const forbidden of [
      "child_process",
      "spawn",
      "exec(",
      "execSync",
      "node:fs",
      'require("fs")',
      "shell",
      "git clone",
      "eval",
      "Function(",
      "writeFile",
      "rm -rf",
      "curl ",
    ]) {
      expect(source).not.toContain(forbidden);
    }
  });

  it("end-to-end: request, approve and verify the backend-issued identifiers", async () => {
    const user = userEvent.setup();
    mockApprovalFlow({
      detail: detail({ approval: null }),
      afterCreate: detail({ approval: { ...APPROVAL_CREATED } }),
      afterApprove: detail({ approval: { ...APPROVAL_APPROVED } }),
    });
    renderPage();
    await loaded();
    const section = approvalSection();
    expect(
      within(section).getByRole("button", { name: "Request Approval" }),
    ).toBeInTheDocument();
    await user.click(
      within(section).getByRole("button", { name: "Request Approval" }),
    );
    await within(section).findByText("Pending");
    expect(within(section).getByText("ap-9")).toBeInTheDocument();
    expect(within(section).getByText("Remediation")).toBeInTheDocument();
    expect(within(section).getByText("1")).toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Approve" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Reason"), "Verified and proof reviewed.");
    await user.click(within(dialog).getByRole("button", { name: "Approve" }));
    await within(section).findByText("Approved \u2014 action authorized.");
    expect(within(section).getAllByText("security-analyst").length).toBeGreaterThan(0);
    const history = within(section).getByRole("list", { name: "Approval history" });
    expect(
      await within(history).findByText("Request created \u2192 Pending"),
    ).toBeInTheDocument();
    expect(
      await within(history).findByText("Pending \u2192 Approved"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

/* ----------------------------------------------------- remediation */

const PROPOSAL_OUT = {
  finding_id: "f-sql-1",
  vulnerability_type: "sql_injection",
  file: "users.py",
  line: 27,
  strategy: "parameterize_query",
  before: "    cursor.execute(query)",
  after: '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
  import_to_add: null,
  rationale:
    "Parameterized query: interpolated values are passed as query parameters instead of being embedded in the SQL text, so user input can no longer alter the statement structure.",
};

const REMEDIATION_PROPOSED = {
  finding_id: "f-sql-1",
  approval_id: "ap-1",
  status: "proposed",
  proposal: PROPOSAL_OUT,
  applied_at: null,
  applied_by: null,
  verified_at: null,
  verification: null,
  error: null,
  created_at: "2026-08-15T12:00:00Z",
};

const REMEDIATION_APPLIED = {
  ...REMEDIATION_PROPOSED,
  status: "applied",
  applied_at: "2026-08-15T12:05:00Z",
  applied_by: "security-analyst",
};

const REMEDIATION_VERIFIED = {
  ...REMEDIATION_APPLIED,
  status: "verified",
  verified_at: "2026-08-15T12:30:00Z",
  verification: "verified",
};

const REMEDIATION_STILL_PRESENT = {
  ...REMEDIATION_APPLIED,
  status: "still_present",
  verified_at: "2026-08-15T12:30:00Z",
  verification: "still_present",
};

const REMEDIATION_NO_FIX = {
  finding_id: "f-sql-1",
  approval_id: "ap-1",
  status: "no_fix_available",
  proposal: {
    finding_id: "f-sql-1",
    vulnerability_type: "ssrf",
    file: "users.py",
    line: 40,
    strategy: "no_automatic_fix",
    before: 'requests.get(url)',
    after: 'requests.get(url)',
    import_to_add: null,
    rationale:
      "no deterministic automatic fix is defined for ssrf; manual remediation is required",
  },
  applied_at: null,
  applied_by: null,
  verified_at: null,
  verification: null,
  error: null,
  created_at: "2026-08-15T12:00:00Z",
};

function remediationDetail(
  remediation: unknown,
  approvalStatus: "approved" | "pending" = "approved",
) {
  return detail({
    approval: {
      ...detail({}).approval!,
      status: approvalStatus,
      action: "remediation",
    },
    remediation: remediation as FindingDetail["remediation"],
    project: {
      project_id: "proj-1",
      name: "repo-a",
      source_type: "directory",
      location: "/tmp/repo-a",
      language: "python",
    },
  });
}

function mockRemediationFlow(options: {
  initialRecord?: unknown;
  detailPayload?: FindingDetail;
  proposalResponse?: MockResponse;
  applyResponse?: MockResponse;
  verifyResponse?: MockResponse;
  reprepareResponse?: MockResponse;
  onCall?: (url: string, init?: RequestInit) => void;
}) {
  let record = options.initialRecord ?? null;
  const fetchMock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      options.onCall?.(url, init);
      const payload = options.detailPayload ?? remediationDetail(record);
      if (method === "GET" && url === "/api/findings/f-sql-1") {
        return { ok: true, status: 200, json: async () => payload };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/approval") {
        return { ok: true, status: 200, json: async () => (payload as FindingDetail).approval };
      }
      if (method === "GET" && url === "/api/approvals/ap-1/history") {
        return { ok: true, status: 200, json: async () => APPROVAL_HISTORY };
      }
      if (method === "GET" && url === "/api/findings/f-sql-1/remediation") {
        if (record) {
          return { ok: true, status: 200, json: async () => record };
        }
        return {
          ok: false,
          status: 404,
          json: async () => ({ detail: "no remediation record for finding: f-sql-1" }),
        };
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/remediation/proposal") {
        record = REMEDIATION_PROPOSED;
        return options.proposalResponse ?? {
          ok: true,
          status: 200,
          json: async () => record,
        };
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/remediation/apply") {
        if (options.applyResponse) return options.applyResponse;
        record = REMEDIATION_APPLIED;
        return { ok: true, status: 200, json: async () => record };
      }
      if (method === "POST" && url === "/api/findings/f-sql-1/remediation/verify") {
        if (options.verifyResponse) return options.verifyResponse;
        record = REMEDIATION_VERIFIED;
        return { ok: true, status: 200, json: async () => record };
      }
      if (method === "POST" && url === "/api/projects/proj-1/reprepare") {
        return options.reprepareResponse ?? {
          ok: true,
          status: 200,
          json: async () => ({ id: "proj-1" }),
        };
      }
      throw new Error(`unexpected request: ${method} ${url}`);
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function remediationSection() {
  const title = screen.getByRole("heading", { name: "Remediation" });
  return title.closest("section") as HTMLElement;
}

describe("finding remediation workflow", () => {
  it("explains the gate when no approved approval exists", async () => {
    mockRemediationFlow({
      detailPayload: remediationDetail(null, "pending"),
    });
    renderPage();
    await loaded();
    const section = remediationSection();
    expect(
      within(section).getByText(/remediation requires an approved approval/),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Generate Fix Proposal" }),
    ).not.toBeInTheDocument();
  });

  it("proposes a fix and shows the diff and confirmation gate", async () => {
    const user = userEvent.setup();
    mockRemediationFlow({});
    renderPage();
    await loaded();
    const section = remediationSection();
    await user.click(
      within(section).getByRole("button", { name: "Generate Fix Proposal" }),
    );
    expect(await within(section).findByText("Proposed")).toBeInTheDocument();
    expect(within(section).getByText("Parameterized Query")).toBeInTheDocument();
    expect(within(section).getByText("users.py:27")).toBeInTheDocument();
    expect(
      within(section).getByText(PROPOSAL_OUT.before.trim()),
    ).toBeInTheDocument();
    expect(
      within(section).getByText(PROPOSAL_OUT.after.trim()),
    ).toBeInTheDocument();
    const applyButton = within(section).getByRole("button", {
      name: "Apply Fix to Workspace Copy",
    });
    expect(applyButton).toBeDisabled();
    await user.click(
      within(section).getByRole("checkbox", {
        name: /I understand this patches the private workspace copy/,
      }),
    );
    expect(applyButton).toBeEnabled();
  });

  it("applies with confirmation, then re-prepares and verifies", async () => {
    const user = userEvent.setup();
    mockRemediationFlow({ initialRecord: REMEDIATION_PROPOSED });
    renderPage();
    await loaded();
    const section = remediationSection();
    await user.click(
      within(section).getByRole("checkbox", {
        name: /I understand this patches the private workspace copy/,
      }),
    );
    await user.click(
      within(section).getByRole("button", { name: "Apply Fix to Workspace Copy" }),
    );
    expect(await within(section).findByText("Applied")).toBeInTheDocument();
    expect(within(section).getByText("security-analyst")).toBeInTheDocument();

    await user.click(
      within(section).getByRole("button", { name: "Re-prepare & Rescan" }),
    );
    await user.click(
      within(section).getByRole("button", { name: "Verify Fix" }),
    );
    expect(
      await within(section).findByText(/no longer produces this finding/),
    ).toBeInTheDocument();
  });

  it("reports still_present when a fresh scan still produces the finding", async () => {
    const user = userEvent.setup();
    const fetchMock = mockRemediationFlow({
      initialRecord: REMEDIATION_APPLIED,
      verifyResponse: {
        ok: true,
        status: 200,
        json: async () => REMEDIATION_STILL_PRESENT,
      },
    });
    renderPage();
    await loaded();
    const section = remediationSection();
    await user.click(
      within(section).getByRole("button", { name: "Verify Fix" }),
    );
    expect(
      await within(section).findByText(/still produces this finding/),
    ).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalled();
  });

  it("shows manual remediation guidance for no_fix_available", async () => {
    mockRemediationFlow({ initialRecord: REMEDIATION_NO_FIX });
    renderPage();
    await loaded();
    const section = remediationSection();
    expect(within(section).getAllByText("No Automatic Fix").length).toBeGreaterThan(0);
    expect(
      within(section).getAllByText(/manual remediation is required/).length,
    ).toBeGreaterThan(0);
    expect(
      within(section).queryByRole("button", { name: "Apply Fix to Workspace Copy" }),
    ).not.toBeInTheDocument();
  });

  it("surfaces backend gate errors instead of fabricating success", async () => {
    const user = userEvent.setup();
    mockRemediationFlow({
      initialRecord: REMEDIATION_PROPOSED,
      applyResponse: {
        ok: false,
        status: 409,
        json: async () => ({ detail: "source changed since the proposal was generated" }),
      },
    });
    renderPage();
    await loaded();
    const section = remediationSection();
    await user.click(
      within(section).getByRole("checkbox", {
        name: /I understand this patches the private workspace copy/,
      }),
    );
    await user.click(
      within(section).getByRole("button", { name: "Apply Fix to Workspace Copy" }),
    );
    expect(
      await within(section).findByText(/source changed since the proposal/),
    ).toBeInTheDocument();
  });

  it("triggers no other pipeline stage during the remediation workflow", async () => {
    const user = userEvent.setup();
    const onCall = vi.fn<(url: string, init?: RequestInit) => void>();
    mockRemediationFlow({
      initialRecord: REMEDIATION_PROPOSED,
      onCall,
    });
    renderPage();
    await loaded();
    const section = remediationSection();
    await user.click(
      within(section).getByRole("checkbox", {
        name: /I understand this patches the private workspace copy/,
      }),
    );
    await user.click(
      within(section).getByRole("button", { name: "Apply Fix to Workspace Copy" }),
    );
    await within(section).findByText("Applied");
    await user.click(
      within(section).getByRole("button", { name: "Re-prepare & Rescan" }),
    );
    await user.click(
      within(section).getByRole("button", { name: "Verify Fix" }),
    );
    await within(section).findByText(/no longer produces this finding/);
    expect(onCall.mock.calls.length).toBeGreaterThan(0);
    for (const [url, init] of onCall.mock.calls) {
      const method = (init?.method ?? "GET").toUpperCase();
      const path = String(url);
      const allowed =
        (method === "GET" && path === "/api/findings/f-sql-1") ||
        (method === "GET" && path === "/api/findings/f-sql-1/approval") ||
        (method === "GET" && path === "/api/findings/f-sql-1/remediation") ||
        (method === "GET" && path === "/api/approvals/ap-1/history") ||
        (method === "POST" && path === "/api/findings/f-sql-1/remediation/proposal") ||
        (method === "POST" && path === "/api/findings/f-sql-1/remediation/apply") ||
        (method === "POST" && path === "/api/findings/f-sql-1/remediation/verify") ||
        (method === "POST" && path === "/api/projects/proj-1/reprepare");
      expect(allowed).toBe(true);
    }
    for (const [url, init] of onCall.mock.calls) {
      const path = String(url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (method !== "POST") continue;
      for (const stage of [
        "/scan",
        "/deduplicate",
        "/validate",
        "/prove",
        "/risk",
        "/sla",
        "/approval",
      ]) {
        expect(path).not.toContain(stage);
      }
    }
  });
});
