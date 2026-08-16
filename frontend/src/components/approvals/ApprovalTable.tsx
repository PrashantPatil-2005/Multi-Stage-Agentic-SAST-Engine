import type { KeyboardEvent } from "react";
import { Link } from "react-router-dom";

import type { ApprovalListItem } from "../../api/approvals";
import { Button } from "../ui/Button";
import { Badge } from "../ui/Badge";
import { priorityTone, vulnLabel } from "../findings/findingsHelpers";
import { ApprovalStatusBadge } from "./ApprovalStatusBadge";
import {
  approvalActionLabel,
  formatRequestedDate,
  shortFindingId,
} from "./approvalsHelpers";

export interface ApprovalTableProps {
  items: ApprovalListItem[];
  selectedApprovalId: string | null;
  onSelect: (item: ApprovalListItem) => void;
  onOpenFinding: (item: ApprovalListItem) => void;
}

function ReviewButton({
  item,
  selectedApprovalId,
  onSelect,
}: {
  item: ApprovalListItem;
  selectedApprovalId: string | null;
  onSelect: (item: ApprovalListItem) => void;
}) {
  const actionable =
    item.status === "pending" || item.status === "changes_requested";
  const isSelected = item.approval_id === selectedApprovalId;
  if (!actionable) return <span className="ap-table__none">{"\u2014"}</span>;
  return (
    <Button
      size="sm"
      variant={isSelected ? "primary" : "secondary"}
      onClick={(event) => {
        event.stopPropagation();
        onSelect(item);
      }}
    >
      {isSelected ? "Reviewing" : "Review"}
    </Button>
  );
}

export function ApprovalTable({
  items,
  selectedApprovalId,
  onSelect,
  onOpenFinding,
}: ApprovalTableProps) {
  const handleRowKeyDown = (item: ApprovalListItem) => (event: KeyboardEvent<HTMLElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onOpenFinding(item);
    }
  };

  return (
    <>
      <div className="ap-table-wrap">
        <table className="ap-table">
          <caption className="visually-hidden">
            Approval review queue
          </caption>
          <thead>
            <tr>
              <th scope="col">Finding</th>
              <th scope="col">Vulnerability</th>
              <th scope="col">Priority</th>
              <th scope="col">Risk</th>
              <th scope="col">Requested By</th>
              <th scope="col">Requested At</th>
              <th scope="col">Action</th>
              <th scope="col">Status</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr
                key={item.approval_id}
                className="ap-table__row"
                onClick={() => onOpenFinding(item)}
                onKeyDown={handleRowKeyDown(item)}
                tabIndex={0}
              >
                <td>
                  <Link
                    className="ap-table__finding-link"
                    to={`/findings/${item.finding_id}`}
                    onClick={(event) => event.stopPropagation()}
                  >
                    <span className="ap-table__id" title={item.finding_id}>
                      {shortFindingId(item.finding_id)}
                    </span>
                  </Link>
                </td>
                <td className="ap-table__vuln">
                  {vulnLabel(item.vulnerability_type ?? item.finding_id)}
                </td>
                <td>
                  {item.priority ? (
                    <Badge tone={priorityTone(item.priority)}>
                      {item.priority}
                    </Badge>
                  ) : (
                    <span className="ap-table__none">{"\u2014"}</span>
                  )}
                </td>
                <td className="ap-table__risk">
                  {item.risk_score !== null ? item.risk_score : "\u2014"}
                </td>
                <td>{item.requested_by}</td>
                <td>{formatRequestedDate(item.requested_at)}</td>
                <td>{approvalActionLabel(item.action)}</td>
                <td>
                  <ApprovalStatusBadge status={item.status} />
                </td>
                <td>
                  <ReviewButton
                    item={item}
                    selectedApprovalId={selectedApprovalId}
                    onSelect={onSelect}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ul className="ap-cards" aria-label="Approval requests">
        {items.map((item) => (
          <li
            key={item.approval_id}
            className="ap-card"
            onClick={() => onOpenFinding(item)}
            onKeyDown={handleRowKeyDown(item)}
            tabIndex={0}
          >
            <div className="ap-card__head">
              <span
                className="ap-card__vuln"
                onClick={(event) => event.stopPropagation()}
              >
                <Link
                  className="ap-card__link"
                  to={`/findings/${item.finding_id}`}
                >
                  {vulnLabel(item.vulnerability_type ?? item.finding_id)}
                </Link>
              </span>
              <ApprovalStatusBadge status={item.status} />
            </div>
            <dl className="ap-card__meta">
              <div>
                <dt>Finding</dt>
                <dd title={item.finding_id}>{shortFindingId(item.finding_id)}</dd>
              </div>
              <div>
                <dt>Priority</dt>
                <dd>{item.priority ?? "\u2014"}</dd>
              </div>
              <div>
                <dt>Risk</dt>
                <dd>{item.risk_score !== null ? item.risk_score : "\u2014"}</dd>
              </div>
              <div>
                <dt>Requested</dt>
                <dd>{formatRequestedDate(item.requested_at)}</dd>
              </div>
              <div>
                <dt>Action</dt>
                <dd>{approvalActionLabel(item.action)}</dd>
              </div>
            </dl>
            <div className="ap-card__actions">
              <ReviewButton
                item={item}
                selectedApprovalId={selectedApprovalId}
                onSelect={onSelect}
              />
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
