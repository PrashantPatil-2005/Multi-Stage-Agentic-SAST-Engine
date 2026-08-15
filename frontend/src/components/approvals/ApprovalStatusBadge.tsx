import type { ApprovalStatus } from "../../api/approvals";
import { Badge } from "../ui/Badge";
import { approvalStatusLabel, approvalStatusTone } from "./approvalsHelpers";

export function ApprovalStatusBadge({ status }: { status: ApprovalStatus }) {
  return (
    <Badge tone={approvalStatusTone(status)}>{approvalStatusLabel(status)}</Badge>
  );
}
