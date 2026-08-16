import { Link } from "react-router-dom";

import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "./not-found.css";

export function NotFoundPage() {
  return (
    <div className="nf-page">
      <PageHeader
        title="Page not found"
        description="The page you are looking for does not exist."
      />
      <Card>
        <div className="nf-body" role="status">
          <p className="nf-body__text">
            The requested page could not be found. The link may be out of
            date, or the address may be incorrect.
          </p>
          <div className="nf-body__actions">
            <Link
              className="ui-button ui-button--primary ui-button--md"
              to="/dashboard"
            >
              Return to Dashboard
            </Link>
            <Link
              className="ui-button ui-button--secondary ui-button--md"
              to="/findings"
            >
              Go to Findings
            </Link>
          </div>
        </div>
      </Card>
    </div>
  );
}
