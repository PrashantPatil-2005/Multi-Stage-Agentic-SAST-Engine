import {
  BellIcon,
  MenuIcon,
  MoonIcon,
  SearchIcon,
  SunIcon,
} from "./icons";
import { useTheme } from "../theme/ThemeContext";
import { useAuth } from "../context/AuthContext";
import { IconButton } from "./ui/IconButton";
import "./topbar.css";

interface TopBarProps {
  title: string;
  onOpenDrawer: () => void;
}

export function TopBar({ title, onOpenDrawer }: TopBarProps) {
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();

  const initials = user
    ? user.display_name
        .split(" ")
        .map((w) => w[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "??";

  return (
    <header className="topbar">
      <div className="topbar__left">
        <IconButton
          label="Open navigation menu"
          className="topbar__menu"
          onClick={onOpenDrawer}
        >
          <MenuIcon />
        </IconButton>
        <span className="topbar__title">{title}</span>
      </div>

      <div className="topbar__right">
        <div className="topbar__search" role="search">
          <span className="topbar__search-icon" aria-hidden="true">
            <SearchIcon />
          </span>
          <input
            type="search"
            className="topbar__search-input"
            placeholder="Search findings\u2026"
            aria-label="Search (coming soon)"
            disabled
          />
          <span className="topbar__search-hint">Coming soon</span>
        </div>

        <button
          type="button"
          className="topbar__select"
          aria-label="Repository selector (coming soon)"
          disabled
        >
          <span className="topbar__select-text">All repositories</span>
          <span className="topbar__select-caret" aria-hidden="true">&#9662;</span>
        </button>

        <IconButton label="Notifications (coming soon)" disabled>
          <BellIcon />
        </IconButton>

        <IconButton
          label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
          onClick={toggleTheme}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </IconButton>

        <button
          type="button"
          className="topbar__profile"
          aria-label="Profile"
          disabled
        >
          <span className="topbar__avatar" aria-hidden="true">
            {initials}
          </span>
          <span className="topbar__profile-name">
            {user?.display_name ?? "Unknown"}
          </span>
        </button>
      </div>
    </header>
  );
}
