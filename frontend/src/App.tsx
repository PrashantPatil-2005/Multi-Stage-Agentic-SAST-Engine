import { useEffect, useMemo, useState } from "react";
import { Route, Routes, useLocation, useNavigate } from "react-router-dom";

import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProfilePage } from "./pages/ProfilePage";
import { ProofPage } from "./pages/ProofPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { RiskPage } from "./pages/RiskPage";
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
  const navigate = useNavigate();

  const route = useMemo(() => {
    const findingsDetail =
      location.pathname.startsWith("/findings/") &&
      location.pathname !== "/findings";
    if (findingsDetail) return PAGES.find((p) => p.path === "/findings")!;
    return PAGES.find((p) => p.path === location.pathname) ?? PAGES[0];
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

  /* unknown routes land on the dashboard */
  useEffect(() => {
    const findingsDetail =
      location.pathname.startsWith("/findings/") &&
      location.pathname !== "/findings";
    if (!findingsDetail && !PAGES.some((p) => p.path === location.pathname)) {
      navigate("/dashboard", { replace: true });
    }
  }, [location.pathname, navigate]);

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
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/validation" element={<ValidationPage />} />
            <Route path="/proof" element={<ProofPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/benchmarks" element={<BenchmarkPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}