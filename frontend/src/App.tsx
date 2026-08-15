import { useEffect, useMemo, useState } from "react";
import { Route, Routes, useLocation, useNavigate } from "react-router-dom";

import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { ApprovalsPage } from "./pages/ApprovalsPage";
import { BenchmarkPage } from "./pages/BenchmarkPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProofPage } from "./pages/ProofPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { RiskPage } from "./pages/RiskPage";
import { ValidationPage } from "./pages/ValidationPage";
import { ROUTES, PlaceholderPage } from "./pages/PlaceholderPage";
import "./styles/shell.css";

export default function App() {
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  const route = useMemo(() => {
    const findingsDetail =
      location.pathname.startsWith("/findings/") &&
      location.pathname !== "/findings";
    if (findingsDetail) return ROUTES.find((r) => r.path === "/findings")!;
    return ROUTES.find((r) => r.path === location.pathname) ?? ROUTES[0];
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
    if (
      !findingsDetail &&
      !ROUTES.some((r) => r.path === location.pathname)
    ) {
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
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingDetailPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/risk" element={<RiskPage />} />
            <Route path="/validation" element={<ValidationPage />} />
            <Route path="/proof" element={<ProofPage />} />
            <Route path="/benchmarks" element={<BenchmarkPage />} />
            <Route path="/repositories" element={<RepositoriesPage />} />
            {ROUTES.filter(
              (r) =>
                r.path !== "/findings" &&
                r.path !== "/approvals" &&
                r.path !== "/risk" &&
                r.path !== "/validation" &&
                r.path !== "/proof" &&
                r.path !== "/benchmarks" &&
                r.path !== "/repositories",
            ).map((r) => (
              <Route
                key={r.path}
                path={r.path}
                element={
                  r.path === "/dashboard" ? (
                    <DashboardPage title={r.title} description={r.description} />
                  ) : (
                    <PlaceholderPage route={r} />
                  )
                }
              />
            ))}
          </Routes>
        </main>
      </div>
    </div>
  );
}