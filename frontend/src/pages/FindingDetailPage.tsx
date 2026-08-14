import { Link } from "react-router-dom";

import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import "./placeholder.css";

export function FindingDetailPage() {
  return (
    <>
      <PageHeader
        title="Finding Detail"
        description="Detailed analysis of a single security finding."
        actions={
          <Link
            className="ui-button ui-button--secondary ui-button--md"
            to="/findings"
          >
            Back to Findings
          </Link>
        }
      />
      <Card title="Finding Detail">
        <div className="placeholder">
          <Badge tone="info">Phase 4</Badge>
          <p className="placeholder__text">
            The finding detail page is coming in Phase 4. This is only the
            navigation target for findings from the list.
          </p>
        </div>
      </Card>
    </>
  );
}