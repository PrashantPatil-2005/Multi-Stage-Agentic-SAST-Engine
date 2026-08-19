import { Link } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
import { useDashboard } from "../hooks/useDashboard";
import { CriticalFindings } from "../components/dashboard/CriticalFindings";
import { MetricCard } from "../components/dashboard/MetricCard";
import { PipelineOverview } from "../components/dashboard/PipelineOverview";
import { RecentActivity } from "../components/dashboard/RecentActivity";
import { RecentScanRuns } from "../components/dashboard/RecentScanRuns";
import { SlaSummary } from "../components/dashboard/SlaSummary";
import { VerificationSummary } from "../components/dashboard/VerificationSummary";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "../components/dashboard/dashboard.css";

/* ------------------------------------------------------------------ */
/*  Role-specific quick actions                                        */
/* ------------------------------------------------------------------ */

interface QuickAction {
  label: string;
  to: string;
}

const ANALYST_ACTIONS: QuickAction[] = [
  { label: "View Findings", to: "/findings" },
  { label: "Scan Repository", to: "/repositories" },
  { label: "Validate Finding", to: "/validation" },
  { label: "Prove Finding", to: "/proof" },
  { label: "Assess Risk", to: "/risk" },
  { label: "Request Approval", to: "/approvals" },
];

const MANAGER_ACTIONS: QuickAction[] = [
  { label: "Review Approvals", to: "/approvals" },
  { label: "View Findings", to: "/findings" },
  { label: "Review Risk & SLA", to: "/risk" },
  { label: "View Remediation", to: "/findings" },
  { label: "View Benchmarks", to: "/benchmarks" },
];

const DEVELOPER_ACTIONS: QuickAction[] = [
  { label: "View Findings", to: "/findings" },
  { label: "View Remediation", to: "/findings" },
  { label: "Scan Repository", to: "/repositories" },
  { label: "View Scan Runs", to: "/repositories" },
];

const AUDITOR_SECTIONS: QuickAction[] = [
  { label: "View Findings", to: "/findings" },
  { label: "View Risk & SLA", to: "/risk" },
  { label: "View Validation", to: "/validation" },
  { label: "View Proof", to: "/proof" },
  { label: "View Approvals", to: "/approvals" },
  { label: "View Benchmarks", to: "/benchmarks" },
];

function QuickActions({
  title,
  actions,
}: {
  title: string;
  actions: QuickAction[];
}) {
  return (
    <Card title={title}>
      <div className="dash-quick-actions" role="list" aria-label={title}>
        {actions.map((action) => (
          <Link
            key={action.to + action.label}
            to={action.to}
            className="ui-button ui-button--secondary ui-button--sm dash-quick-action"
            role="listitem"
          >
            {action.label}
          </Link>
        ))}
      </div>
    </Card>
  );
}

function RoleSubtitle({ role }: { role: string }) {
  const subtitles: Record<string, string> = {
    analyst: "Investigate findings, validate, and triage security issues.",
    manager: "Review approvals, oversee remediation, and manage security posture.",
    developer: "Fix vulnerabilities and verify remediations.",
    auditor: "Read-only visibility into security posture and audit evidence.",
  };
  return (
    <p className="dash-role-subtitle" aria-label={`Dashboard for ${role}`}>
      {subtitles[role] ?? "Security posture at a glance."}
    </p>
  );
}

/* ------------------------------------------------------------------ */
/*  Skeletons                                                         */
/* ------------------------------------------------------------------ */

function KpiSkeleton() {
  return (
    <Card>
      <div className="dash-skeleton dash-skeleton--kpi" aria-hidden="true" />
    </Card>
  );
}

function SectionSkeleton({ title }: { title: string }) {
  return (
    <Card title={title}>
      <div className="dash-skeleton dash-skeleton--line" aria-hidden="true" />
      <div
        className="dash-skeleton dash-skeleton--line"
        style={{ marginTop: 10, width: "60%" }}
        aria-hidden="true"
      />
      <div
        className="dash-skeleton dash-skeleton--block"
        style={{ marginTop: 12 }}
        aria-hidden="true"
      />
    </Card>
  );
}

export interface DashboardPageProps {
  title?: string;
  description?: string;
}

export function DashboardPage({
  title = "Overview",
  description = "Security posture at a glance.",
}: DashboardPageProps) {
  const { user } = useAuth();
  const { summary, projects, loading, error, reload } = useDashboard();
  const role = user?.role;

  const pageDescription = role ? undefined : description;

  return (
    <>
      <PageHeader
        title={title}
        description={pageDescription}
        actions={
          projects.length > 0 ? (
            <label className="dash-repo-select">
              <span className="dash-repo-select__label">Repository</span>
              <select
                className="dash-repo-select__control"
                aria-label="Repository"
                disabled
              >
                <option value="all">All repositories</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
              <span className="dash-repo-select__hint">
                (coming soon)
              </span>
            </label>
          ) : (
            <span className="dash-repo-select__label">No repositories</span>
          )
        }
      />

      {role && <RoleSubtitle role={role} />}

      {loading ? (
        <div aria-busy="true">
          <div className="dash-kpi-grid">
            {[0, 1, 2, 3, 4].map((index) => (
              <KpiSkeleton key={index} />
            ))}
          </div>
          <SectionSkeleton title="Pipeline" />
          <div className="dash-layout" style={{ marginTop: 20 }}>
            <SectionSkeleton title="Critical findings" />
            <div className="dash-column">
              <SectionSkeleton title="SLA summary" />
              <SectionSkeleton title="Verification" />
            </div>
          </div>
        </div>
      ) : error || summary === null ? (
        <Card>
          <div className="dash-error" role="alert" aria-label="Security data error">
            <p className="dash-error__text">
              Unable to load security data. Please try again.
            </p>
            <Button variant="secondary" onClick={reload}>
              Retry
            </Button>
          </div>
        </Card>
      ) : (
        <>
          {projects.length === 0 && summary.kpis.total_findings.value === 0 ? (
            <div className="dash-banner" role="status">
              <p className="dash-banner__text">
                No repositories yet — run a scan to populate the security
                dashboard.
              </p>
              {role !== "auditor" && (
                <Link
                  className="ui-button ui-button--secondary ui-button--md"
                  to="/repositories"
                >
                  Go to Repositories
                </Link>
              )}
            </div>
          ) : null}

          {/* ---- KPI cards ---- */}
          <div
            className="dash-kpi-grid"
            role="region"
            aria-label="Key metrics"
          >
            <MetricCard
              label="Total Findings"
              available={summary.kpis.total_findings.available}
              value={summary.kpis.total_findings.value}
              supporting="detected by static analysis"
              to="/findings"
            />
            <MetricCard
              label="Critical / P0"
              available={summary.kpis.critical_p0.available}
              value={summary.kpis.critical_p0.value}
              supporting="highest-priority issues"
              tone="danger"
              to="/risk"
            />
            <MetricCard
              label="SLA Breaches"
              available={summary.kpis.sla_breaches.available}
              value={summary.kpis.sla_breaches.value}
              supporting="past remediation deadline"
              tone="danger"
              to="/risk"
            />
            <MetricCard
              label="Pending Validation"
              available={summary.kpis.pending_validation.available}
              value={summary.kpis.pending_validation.value}
              supporting="awaiting triage"
              tone="warning"
              to="/validation"
            />
            <MetricCard
              label="Pending Approval"
              available={summary.kpis.pending_approval.available}
              value={summary.kpis.pending_approval.value}
              supporting="awaiting human review"
              tone="warning"
              to="/approvals"
            />
          </div>

          {/* ---- Pipeline ---- */}
          <div className="dash-column" style={{ marginBottom: 20 }}>
            <PipelineOverview stages={summary.pipeline} />
          </div>

          {/* ---- Role-specific quick actions ---- */}
          {role === "analyst" && (
            <QuickActions title="Quick Actions" actions={ANALYST_ACTIONS} />
          )}
          {role === "manager" && (
            <QuickActions title="Quick Actions" actions={MANAGER_ACTIONS} />
          )}
          {role === "developer" && (
            <QuickActions title="Quick Actions" actions={DEVELOPER_ACTIONS} />
          )}
          {role === "auditor" && (
            <QuickActions title="Navigation" actions={AUDITOR_SECTIONS} />
          )}

          {/* ---- Critical findings + SLA + Verification ---- */}
          <div className="dash-layout">
            <CriticalFindings findings={summary.critical_findings} />
            <div className="dash-column">
              <SlaSummary sla={summary.sla} />
              <VerificationSummary verification={summary.verification} />
            </div>
          </div>

          {/* ---- Recent activity + scan runs ---- */}
          <div className="dash-column" style={{ marginTop: 20 }}>
            <RecentActivity items={summary.recent_activity} />
            <RecentScanRuns
              projectNames={new Map(projects.map((p) => [p.id, p.name]))}
            />
          </div>
        </>
      )}
    </>
  );
}