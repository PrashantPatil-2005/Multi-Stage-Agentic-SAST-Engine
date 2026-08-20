/* Report generation button component. */

import { useState } from "react";

import { useReportGeneration } from "../../hooks/useReportGeneration";
import { Button } from "../ui/Button";

interface ReportButtonProps {
  projectId?: string;
  variant?: "primary" | "secondary";
  size?: "sm" | "md";
}

export function ReportButton({
  projectId,
  variant = "secondary",
  size = "md",
}: ReportButtonProps) {
  const { generating, error, generatePdf, generateJson, clearError } =
    useReportGeneration();
  const [showMenu, setShowMenu] = useState(false);

  return (
    <div className="report-button-container" style={{ position: "relative" }}>
      <Button
        variant={variant}
        size={size}
        onClick={() => setShowMenu(!showMenu)}
        disabled={generating}
      >
        {generating ? "Generating..." : "Generate Report"}
      </Button>

      {showMenu && !generating && (
        <div
          className="report-menu"
          role="menu"
          style={{
            position: "absolute",
            top: "100%",
            right: 0,
            marginTop: 4,
            background: "white",
            border: "1px solid #e2e8f0",
            borderRadius: 6,
            boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
            zIndex: 100,
            minWidth: 150,
          }}
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setShowMenu(false);
              generatePdf(projectId);
            }}
            style={{
              display: "block",
              width: "100%",
              padding: "8px 12px",
              textAlign: "left",
              border: "none",
              background: "transparent",
              cursor: "pointer",
            }}
          >
            Download PDF
          </button>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setShowMenu(false);
              generateJson(projectId);
            }}
            style={{
              display: "block",
              width: "100%",
              padding: "8px 12px",
              textAlign: "left",
              border: "none",
              background: "transparent",
              cursor: "pointer",
              borderTop: "1px solid #e2e8f0",
            }}
          >
            Download JSON
          </button>
        </div>
      )}

      {error && (
        <div
          role="alert"
          style={{
            position: "absolute",
            top: "100%",
            right: 0,
            marginTop: 4,
            padding: "8px 12px",
            background: "#fef2f2",
            border: "1px solid #fecaca",
            borderRadius: 6,
            color: "#991b1b",
            fontSize: 12,
            maxWidth: 300,
            zIndex: 100,
          }}
        >
          {error}
          <button
            type="button"
            onClick={clearError}
            style={{
              marginLeft: 8,
              border: "none",
              background: "transparent",
              color: "#991b1b",
              cursor: "pointer",
              textDecoration: "underline",
            }}
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}
