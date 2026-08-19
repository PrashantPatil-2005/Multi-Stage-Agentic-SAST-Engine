import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { PageHeader } from "../components/ui/PageHeader";
import { useAuth } from "../context/AuthContext";
import "./profile.css";

export function ProfilePage() {
  const { user, logout } = useAuth();

  if (!user) return null;

  const initials = user.display_name
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div className="profile-page">
      <PageHeader
        title="Profile"
        description="Your authenticated account"
      />
      <Card title="Account">
        <div className="profile-identity">
          <span className="profile-identity__avatar" aria-hidden="true">
            {initials}
          </span>
          <div className="profile-identity__details">
            <p className="profile-identity__name">{user.display_name}</p>
            <p className="profile-identity__username">@{user.username}</p>
            <p className="profile-identity__role">
              <Badge tone="info">{user.role}</Badge>
            </p>
            <p className="profile-identity__note">
              This is a demo account. Role-based access control is enforced
              server-side. Your capabilities are determined by your assigned
              role.
            </p>
            <button className="profile-logout-btn" onClick={logout}>
              Logout
            </button>
          </div>
        </div>
      </Card>
    </div>
  );
}
