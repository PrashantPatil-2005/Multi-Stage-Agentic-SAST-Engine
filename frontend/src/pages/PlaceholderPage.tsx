import type { ComponentType } from "react";

import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";

export interface RouteSpec {
  path: string;
  title: string;
  phase: number;
  description: string;
  icon?: ComponentType;
}

export const ROUTES: RouteSpec[] = [
  {
    path: "/dashboard",
    title: "Overview",
    phase: 2,
    description: "Security posture at a glance.",
  },
  {
    path: "/findings",
    title: "Findings",
    phase: 3,
    description: "Detected vulnerabilities and their lifecycle.",
  },
  {
    path: "/repositories",
    title: "Repositories",
    phase: 2,
    description: "Ingested source repositories.",
  },
  {
    path: "/risk",
    title: "Risk & SLA",
    phase: 3,
    description: "Prioritized risk with SLA deadlines and escalation.",
  },
  {
    path: "/validation",
    title: "Validation",
    phase: 4,
    description: "LLM-assisted verdicts for candidate findings.",
  },
  {
    path: "/proof",
    title: "Proof",
    phase: 4,
    description: "Sandboxed exploitability evidence.",
  },
  {
    path: "/approvals",
    title: "Approvals",
    phase: 4,
    description: "Human-in-the-loop permission workflow.",
  },
  {
    path: "/benchmarks",
    title: "Benchmarks",
    phase: 5,
    description: "Engine vs Semgrep comparison reports.",
  },
  {
    path: "/settings",
    title: "Settings",
    phase: 2,
    description: "Platform configuration.",
  },
  {
    path: "/profile",
    title: "Profile",
    phase: 2,
    description: "Account information.",
  },
];

export function PlaceholderPage({ route }: { route: RouteSpec }) {
  return (
    <>
      <PageHeader title={route.title} description={route.description} />
      <Card title={route.title}>
        <div className="placeholder">
          <Badge tone="info">Phase {route.phase}</Badge>
          <p className="placeholder__text">
            This page is coming in Phase {route.phase}. Navigation is verified;
            content will be added in a later phase.
          </p>
        </div>
      </Card>
    </>
  );
}