import { Link } from "react-router-dom";

import { useDashboard } from "../hooks/useDashboard";
import { CriticalFindings } from "../components/dashboard/CriticalFindings";
import { MetricCard } from "../components/dashboard/MetricCard";
import { PipelineOverview } from "../components/dashboard/PipelineOverview";
import { RecentActivity } from "../components/dashboard/RecentActivity";
import { SlaSummary } from "../components/dashboard/SlaSummary";
import { VerificationSummary } from "../components/dashboard/VerificationSummary";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "../components/dashboard/dashboard.css";

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
  const { summary, projects, loading, error, reload } = useDashboard();

  return (
    <>
      <PageHeader
        title={title}
        description={description}
        actions={
          projects.length > 0 ? (
            <label className="dash-repo-select">
              <span className="dash-repo-select__label">Repository</span>
              <select className="dash-repo-select__control" aria-label="Repository">
                <option value="all">All repositories</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <span className="dash-repo-select__label">No repositories</span>
          )
        }
      />

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
              <Link
                className="ui-button ui-button--secondary ui-button--md"
                to="/repositories"
              >
                Go to Repositories
              </Link>
            </div>
          ) : null}

          <div className="dash-kpi-grid">
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

          <div className="dash-column" style={{ marginBottom: 20 }}>
            <PipelineOverview stages={summary.pipeline} />
          </div>

          <div className="dash-layout">
            <CriticalFindings findings={summary.critical_findings} />
            <div className="dash-column">
              <SlaSummary sla={summary.sla} />
              <VerificationSummary verification={summary.verification} />
            </div>
          </div>

          <div className="dash-column" style={{ marginTop: 20 }}>
            <RecentActivity items={summary.recent_activity} />
          </div>
        </>
      )}
    </>
  );
}