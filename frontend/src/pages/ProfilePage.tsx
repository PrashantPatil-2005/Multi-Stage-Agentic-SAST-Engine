import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { PageHeader } from "../components/ui/PageHeader";
import "./profile.css";

export function ProfilePage() {
  return (
    <div className="profile-page">
      <PageHeader
        title="Profile"
        description="Operator identity (read-only)"
      />
      <Card title="Operator">
        <div className="profile-identity">
          <span className="profile-identity__avatar" aria-hidden="true">
            SA
          </span>
          <div className="profile-identity__details">
            <p className="profile-identity__name">security-analyst</p>
            <p className="profile-identity__role">
              <Badge tone="info">Demo reviewer identity</Badge>
            </p>
            <p className="profile-identity__note">
              No authentication or user management is implemented.
              Decisions in the approval workflow are recorded under this
              static demo identity; it is not a verified human account.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}
