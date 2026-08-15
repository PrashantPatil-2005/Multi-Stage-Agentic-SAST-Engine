import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import type { ApprovalStatus } from "../api/approvals";
import { ApprovalReviewPanel } from "../components/approvals/ApprovalReviewPanel";
import { ApprovalTable } from "../components/approvals/ApprovalTable";
import {
  APPROVAL_TABS,
  approvalStatusLabel,
} from "../components/approvals/approvalsHelpers";
import { Button } from "../components/ui/Button";
import { PageHeader } from "../components/ui/PageHeader";
import { useApprovals } from "../hooks/useApprovals";
import "../components/approvals/approvals.css";

export function ApprovalsPage() {
  const { items, loading, failed, reload } = useApprovals();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<ApprovalStatus | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const available = useMemo(() => {
    const statuses = new Set<ApprovalStatus>();
    for (const item of items) statuses.add(item.status);
    return APPROVAL_TABS.filter((tab) => statuses.has(tab));
  }, [items]);

  const currentTab =
    activeTab && available.includes(activeTab) ? activeTab : available[0] ?? null;

  useEffect(() => {
    if (selectedId && !items.some((item) => item.approval_id === selectedId)) {
      setSelectedId(null);
    }
  }, [items, selectedId]);

  useEffect(() => {
    if (selectedId) return;
    const firstActionable =
      items.find(
        (item) => item.status === "pending" || item.status === "changes_requested",
      ) ?? null;
    if (firstActionable) setSelectedId(firstActionable.approval_id);
  }, [items, selectedId]);

  const selected =
    items.find((item) => item.approval_id === selectedId) ?? null;

  const visible = currentTab
    ? items.filter((item) => item.status === currentTab)
    : [];

  return (
    <div className="approvals-page">
      <PageHeader
        title="Approvals"
        description="Review and authorize security actions"
      />

      {failed ? (
        <div className="ap-page-error" role="alert">
          <p>Unable to load approval requests.</p>
          <Button variant="secondary" size="sm" onClick={reload}>
            Retry
          </Button>
        </div>
      ) : loading ? (
        <div className="ap-page-skeleton" aria-hidden="true">
          <div className="ap-page-skeleton__row" />
          <div className="ap-page-skeleton__row" />
          <div className="ap-page-skeleton__row" />
        </div>
      ) : items.length === 0 ? (
        <div className="ap-empty">
          <h2 className="ap-empty__title">No approval requests</h2>
          <p className="ap-empty__text">
            Approval requests appear here once validated and proven findings
            are flagged for review.
          </p>
        </div>
      ) : (
        <>
          <div className="ap-tabs" role="tablist" aria-label="Approval status">
            {available.map((tab) => {
              const count = items.filter((item) => item.status === tab).length;
              const label = approvalStatusLabel(tab);
              const active = currentTab === tab;
              return (
                <button
                  key={tab}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  aria-controls="approvals-panel"
                  id={`approvals-tab-${tab}`}
                  className={`ap-tabs__tab${active ? " ap-tabs__tab--active" : ""}`}
                  onClick={() => setActiveTab(tab)}
                >
                  {label} <span className="ap-tabs__count">({count})</span>
                </button>
              );
            })}
          </div>

          <div
            id="approvals-panel"
            role="tabpanel"
            aria-labelledby={`approvals-tab-${currentTab}`}
            className="ap-layout"
          >
            <section className="ap-list" aria-label="Approval queue list">
              <ApprovalTable
                items={visible}
                selectedApprovalId={selectedId}
                onSelect={(item) => setSelectedId(item.approval_id)}
                onOpenFinding={(item) =>
                  navigate(`/findings/${item.finding_id}`)
                }
              />
            </section>
            <aside className="ap-review-column" aria-label="Approval review">
              <ApprovalReviewPanel
                approval={selected}
                onStatusChanged={reload}
              />
            </aside>
          </div>
        </>
      )}
    </div>
  );
}
