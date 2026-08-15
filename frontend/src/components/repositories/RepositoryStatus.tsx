import { Badge } from "../ui/Badge";

export interface RepositoryStatusProps {
  status: string;
}

export function RepositoryStatus({ status }: RepositoryStatusProps) {
  const label =
    status.charAt(0).toUpperCase() + status.slice(1).replace(/_/g, " ");
  return (
    <span className="repo-status">
      <Badge tone={status === "prepared" ? "success" : "neutral"}>
        {label}
      </Badge>
    </span>
  );
}
