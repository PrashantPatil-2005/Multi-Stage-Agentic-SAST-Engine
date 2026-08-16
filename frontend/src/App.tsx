import { useEffect, useMemo, useState } from "react";
import { Route, Routes, useLocation } from "react-router-dom";

import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ProfilePage } from "./pages/ProfilePage";
import { ProofPage } from "./pages/ProofPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { RiskPage } from "./pages/RiskPage";
import { ScanRunPage } from "./pages/ScanRunPage";
import { SettingsPage } from "./pages/SettingsPage";
import { ValidationPage } from "./pages/ValidationPage";
import "./styles/shell.css";

interface PageSpec {
  path: string;
  title: string;
}

const PAGES: PageSpec[] = [
  { path: "/dashboard", title: "Overview" },
  { path: "/findings", title: "Findings" },
  { path: "/repositories", title: "Repositories" },
  { path: "/risk", title: "Risk & SLA" },
  { path: "/validation", title: "Validation" },
  { path: "/proof", title: "Proof" },
  { path: "/approvals", title: "Approvals" },
  { path: "/benchmarks", title: "Benchmarks" },
  { path: "/settings", title: "Settings" },
  { path: "/profile", title: "Profile" },
];

export default function App() {
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const location = useLocation();

  const route = useMemo(() => {
    const findingsDetail =
      location.pathname.startsWith("/findings/") &&
      location.pathname !== "/findings";
    if (findingsDetail) return PAGES.find((p) => p.path === "/findings")!;
    const scanRunDetail =
      location.pathname.startsWith("/scans/") && location.pathname !== "/scans";
    if (scanRunDetail) {
      return { path: "/scans/:scanRunId", title: "Scan Run" };
    }
    return (
      PAGES.find((p) => p.path === location.pathname) ?? {
        path: "*",
        title: "Page not found",
      }
    );
  }, [location.pathname]);

  /* close the drawer when the route changes (mobile) */
  useEffect(() => {
    setDrawerOpen(false);
  }, [location.pathname]);

  /* Escape closes the drawer */
  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

  return (
    <div className="shell">
      <div
        className={`shell__scrim${drawerOpen ? " shell__scrim--open" : ""}`}
        aria-hidden="true"
        onClick={() => setDrawerOpen(false)}
      />

      <div
        className={`shell__sidebar${
          drawerOpen ? " shell__sidebar--drawer" : ""
        }`}
      >
        <Sidebar
          collapsed={collapsed}
          onToggleCollapse={() => setCollapsed((c) => !c)}
          drawerOpen={drawerOpen}
          onCloseDrawer={() => setDrawerOpen(false)}
        />
      </div>

      <div className="shell__main">
        <TopBar title={route.title} onOpenDrawer={() => setDrawerOpen(true)} />
        <main className="shell__content">
          <Routes>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/repositories" element={<RepositoriesPage />} />
            <Route path="/scans/:scanRunId" element={<ScanRunPage />} />
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/validation" element={<ValidationPage />} />
            <Route path="/proof" element={<ProofPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/benchmarks" element={<BenchmarkPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}