import { Card } from "../components/ui/Card";
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
            OP
          </span>
          <div className="profile-identity__details">
            <p className="profile-identity__name">Operator</p>
            <p className="profile-identity__note">
              No authentication or user management is implemented. This is a
              static demo identity; sign-in is not part of the product.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
}