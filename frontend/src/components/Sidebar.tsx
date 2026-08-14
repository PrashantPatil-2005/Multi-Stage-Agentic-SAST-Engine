import type { ComponentType, SVGProps } from "react";
import { NavLink } from "react-router-dom";

import {
  ApprovalsIcon,
  BenchmarksIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  FindingsIcon,
  OverviewIcon,
  ProfileIcon,
  ProofIcon,
  RepositoriesIcon,
  RiskIcon,
  SettingsIcon,
  ValidationIcon,
} from "./icons";
import { IconButton } from "./ui/IconButton";
import "./sidebar.css";

export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
}

const PRIMARY_NAV: NavItem[] = [
  { to: "/dashboard", label: "Overview", icon: OverviewIcon },
  { to: "/findings", label: "Findings", icon: FindingsIcon },
  { to: "/repositories", label: "Repositories", icon: RepositoriesIcon },
  { to: "/risk", label: "Risk & SLA", icon: RiskIcon },
  { to: "/validation", label: "Validation", icon: ValidationIcon },
  { to: "/proof", label: "Proof", icon: ProofIcon },
  { to: "/approvals", label: "Approvals", icon: ApprovalsIcon },
  { to: "/benchmarks", label: "Benchmarks", icon: BenchmarksIcon },
];

const SECONDARY_NAV: NavItem[] = [
  { to: "/settings", label: "Settings", icon: SettingsIcon },
  { to: "/profile", label: "Profile", icon: ProfileIcon },
];

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  drawerOpen: boolean;
  onCloseDrawer: () => void;
}

function NavItems({
  items,
  collapsed,
}: {
  items: NavItem[];
  collapsed: boolean;
}) {
  return (
    <ul className="sidebar__list">
      {items.map((item) => (
        <li key={item.to}>
          <NavLink
            to={item.to}
            className={({ isActive }) =>
              `sidebar__link${isActive ? " sidebar__link--active" : ""}`
            }
            aria-current="page"
            title={collapsed ? item.label : undefined}
          >
            <span className="sidebar__link-icon">
              <item.icon />
            </span>
            <span className="sidebar__link-label">{item.label}</span>
          </NavLink>
        </li>
      ))}
    </ul>
  );
}

export function Sidebar({
  collapsed,
  onToggleCollapse,
  drawerOpen,
  onCloseDrawer,
}: SidebarProps) {
  return (
    <nav
      className={`sidebar${collapsed ? " sidebar--collapsed" : ""}${
        drawerOpen ? " sidebar--open" : ""
      }`}
      aria-label="Primary navigation"
    >
      <div className="sidebar__brand">
        <span className="sidebar__brand-mark" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="6" fill="currentColor" />
            <path
              d="M8 16l5 5 11-11"
              stroke="#fff"
              strokeWidth="3"
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        <span className="sidebar__brand-text">SAST Platform</span>
      </div>

      <div className="sidebar__scroll">
        <NavItems items={PRIMARY_NAV} collapsed={collapsed} />

        <div className="sidebar__section" aria-hidden="true">
          <span className="sidebar__section-label">Account</span>
        </div>
        <NavItems items={SECONDARY_NAV} collapsed={collapsed} />
      </div>

      <div className="sidebar__footer">
        <IconButton
          label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={onToggleCollapse}
          className="sidebar__collapse-toggle"
        >
          {collapsed ? <ChevronRightIcon /> : <ChevronLeftIcon />}
        </IconButton>
        <span className="sidebar__collapse-label">
          {collapsed ? "" : "Collapse"}
        </span>
      </div>

      {drawerOpen ? (
        <button
          type="button"
          className="sidebar__close"
          aria-label="Close navigation drawer"
          onClick={onCloseDrawer}
        >
          &times;
        </button>
      ) : null}
    </nav>
  );
}