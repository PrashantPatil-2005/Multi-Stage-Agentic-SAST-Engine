import {
  BellIcon,
  MenuIcon,
  MoonIcon,
  SearchIcon,
  SunIcon,
} from "./icons";
import { useTheme } from "../theme/ThemeContext";
import { IconButton } from "./ui/IconButton";
import "./topbar.css";

interface TopBarProps {
  title: string;
  onOpenDrawer: () => void;
}

export function TopBar({ title, onOpenDrawer }: TopBarProps) {
  const { theme, toggleTheme } = useTheme();

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
        <h1 className="topbar__title">{title}</h1>
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
          />
          <span className="topbar__search-hint">Coming soon</span>
        </div>

        <button type="button" className="topbar__select" aria-label="Repository selector (coming soon)">
          <span className="topbar__select-text">All repositories</span>
          <span className="topbar__select-caret" aria-hidden="true">&#9662;</span>
        </button>

        <IconButton label="Notifications (coming soon)">
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
          aria-label="Profile menu (coming soon)"
        >
          <span className="topbar__avatar" aria-hidden="true">
            OP
          </span>
          <span className="topbar__profile-name">Operator</span>
        </button>
      </div>
    </header>
  );
}