import type { ComponentType, SVGProps } from "react";
import { NavLink } from "react-router-dom";

import { useAuth } from "../context/AuthContext";
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
  roles?: string[]; // If undefined, visible to all
}

const PRIMARY_NAV: NavItem[] = [
  { to: "/dashboard", label: "Overview", icon: OverviewIcon },
  { to: "/repositories", label: "Repositories", icon: RepositoriesIcon },
  { to: "/findings", label: "Findings", icon: FindingsIcon },
  { to: "/risk", label: "Risk & SLA", icon: RiskIcon },
  {
    to: "/validation",
    label: "Validation",
    icon: ValidationIcon,
    roles: ["analyst", "manager", "developer"],
  },
  {
    to: "/proof",
    label: "Proof",
    icon: ProofIcon,
    roles: ["analyst", "manager", "developer"],
  },
  {
    to: "/approvals",
    label: "Approvals",
    icon: ApprovalsIcon,
    roles: ["manager"],
  },
  {
    to: "/benchmarks",
    label: "Benchmarks",
    icon: BenchmarksIcon,
    roles: ["analyst", "manager"],
  },
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
  userRole,
}: {
  items: NavItem[];
  collapsed: boolean;
  userRole: string;
}) {
  const filtered = items.filter(
    (item) => !item.roles || item.roles.includes(userRole)
  );
  return (
    <ul className="sidebar__list">
      {filtered.map((item) => (
        <li key={item.to}>
          <NavLink
            to={item.to}
            className={({ isActive }) =>
              `sidebar__link${isActive ? " sidebar__link--active" : ""}`
            }
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
  const { user, logout } = useAuth();
  const userRole = user?.role ?? "";

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
        <NavItems items={PRIMARY_NAV} collapsed={collapsed} userRole={userRole} />

        <div className="sidebar__section" aria-hidden="true">
          <span className="sidebar__section-label">Account</span>
        </div>
        <NavItems items={SECONDARY_NAV} collapsed={collapsed} userRole={userRole} />
      </div>

      <div className="sidebar__footer">
        {!collapsed && user && (
          <div className="sidebar__user-info">
            <span className="sidebar__user-name">{user.display_name}</span>
            <span className="sidebar__user-role">{user.role}</span>
            <button
              className="sidebar__logout-btn"
              onClick={logout}
              title="Logout"
            >
              Logout
            </button>
          </div>
        )}
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
