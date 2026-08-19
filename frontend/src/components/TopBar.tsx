import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import {
  BellIcon,
  MenuIcon,
  MoonIcon,
  SearchIcon,
  SunIcon,
} from "./icons";
import { useTheme } from "../theme/ThemeContext";
import { useAuth } from "../context/AuthContext";
import { useDebounce } from "../hooks/useDebounce";
import { useFindings } from "../hooks/useFindings";
import { useNotifications } from "../hooks/useNotifications";
import { useRepositories } from "../hooks/useRepositories";
import { IconButton } from "./ui/IconButton";
import type { FindingListItem } from "../api/findings";
import "./topbar.css";

interface TopBarProps {
  title: string;
  onOpenDrawer: () => void;
}

export function TopBar({ title, onOpenDrawer }: TopBarProps) {
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const initials = user
    ? user.display_name
        .split(" ")
        .map((w) => w[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "??";

  // ── Search ────────────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const debouncedSearch = useDebounce(searchQuery.trim(), 300);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const { findings: searchResults, loading: searchLoading } = useFindings(
    undefined,
    debouncedSearch || undefined,
  );

  const displayResults = useMemo(() => {
    if (!debouncedSearch) return [];
    return searchResults.slice(0, 12);
  }, [debouncedSearch, searchResults]);

  const handleSearchFocus = useCallback(() => {
    setSearchOpen(true);
  }, []);

  const handleSearchChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setSearchQuery(e.target.value);
      setSearchOpen(true);
    },
    [],
  );

  const handleSearchKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Escape") {
        setSearchQuery("");
        setSearchOpen(false);
        searchInputRef.current?.blur();
      }
      if (e.key === "Enter" && displayResults.length > 0) {
        navigate(`/findings/${displayResults[0].finding_id}`);
        setSearchOpen(false);
        searchInputRef.current?.blur();
      }
    },
    [displayResults, navigate],
  );

  const handleResultClick = useCallback(
    (findingId: string) => {
      navigate(`/findings/${findingId}`);
      setSearchOpen(false);
      setSearchQuery("");
    },
    [navigate],
  );

  // Close search dropdown on outside click
  useEffect(() => {
    if (!searchOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (
        searchContainerRef.current &&
        !searchContainerRef.current.contains(e.target as Node)
      ) {
        setSearchOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [searchOpen]);

  // ── Repository Selector ───────────────────────────────────────────────
  const [repoOpen, setRepoOpen] = useState(false);
  const repoContainerRef = useRef<HTMLDivElement>(null);
  const { list: repoList, loading: reposLoading } = useRepositories();
  const currentProjectId = searchParams.get("project_id");

  const currentRepoName = useMemo(() => {
    if (!currentProjectId || !repoList) return "All repositories";
    const repo = repoList.repositories.find(
      (r) => r.project_id === currentProjectId,
    );
    return repo?.name ?? "All repositories";
  }, [currentProjectId, repoList]);

  const handleRepoSelect = useCallback(
    (projectId: string | null) => {
      if (projectId) {
        navigate(`/findings?project_id=${encodeURIComponent(projectId)}`);
      } else {
        navigate("/findings");
      }
      setRepoOpen(false);
    },
    [navigate],
  );

  // Close repo dropdown on outside click
  useEffect(() => {
    if (!repoOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (
        repoContainerRef.current &&
        !repoContainerRef.current.contains(e.target as Node)
      ) {
        setRepoOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [repoOpen]);

  // Close repo dropdown on Escape
  useEffect(() => {
    if (!repoOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setRepoOpen(false);
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [repoOpen]);

  // ── Notifications ─────────────────────────────────────────────────────
  const [notifOpen, setNotifOpen] = useState(false);
  const notifContainerRef = useRef<HTMLDivElement>(null);
  const {
    notifications,
    unreadCount,
    loading: notifsLoading,
    markRead,
    markAllRead,
  } = useNotifications();

  const handleNotifClick = useCallback(
    (notification: { finding_id: string | null; id: string }) => {
      markRead(notification.id);
      if (notification.finding_id) {
        navigate(`/findings/${notification.finding_id}`);
      }
      setNotifOpen(false);
    },
    [navigate, markRead],
  );

  // Close notifications dropdown on outside click
  useEffect(() => {
    if (!notifOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (
        notifContainerRef.current &&
        !notifContainerRef.current.contains(e.target as Node)
      ) {
        setNotifOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [notifOpen]);

  // Close notifications dropdown on Escape
  useEffect(() => {
    if (!notifOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNotifOpen(false);
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [notifOpen]);

  // ── Render ────────────────────────────────────────────────────────────
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
        {/* ── Search ──────────────────────────────────────────── */}
        <div
          className="topbar__search"
          role="search"
          ref={searchContainerRef}
        >
          <span className="topbar__search-icon" aria-hidden="true">
            <SearchIcon />
          </span>
          <input
            ref={searchInputRef}
            type="search"
            className="topbar__search-input"
            placeholder="Search findings\u2026"
            aria-label="Search findings"
            value={searchQuery}
            onChange={handleSearchChange}
            onFocus={handleSearchFocus}
            onKeyDown={handleSearchKeyDown}
            autoComplete="off"
          />

          {searchOpen && debouncedSearch && (
            <div
              className="topbar__search-results"
              role="listbox"
              aria-label="Search results"
            >
              {searchLoading ? (
                <div className="topbar__search-status" role="status">
                  Searching\u2026
                </div>
              ) : displayResults.length === 0 ? (
                <div className="topbar__search-status" role="status">
                  No findings found
                </div>
              ) : (
                <ul className="topbar__search-list">
                  {displayResults.map((finding: FindingListItem) => (
                    <li
                      key={finding.finding_id}
                      className="topbar__search-item"
                      role="option"
                      tabIndex={0}
                      onClick={() => handleResultClick(finding.finding_id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter")
                          handleResultClick(finding.finding_id);
                      }}
                    >
                      <span className="topbar__search-item-id">
                        {finding.finding_id.slice(0, 12)}
                      </span>
                      <span className="topbar__search-item-vuln">
                        {finding.vulnerability_type}
                      </span>
                      <span className="topbar__search-item-file">
                        {finding.file}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* ── Repository Selector ─────────────────────────────── */}
        <div className="topbar__select-wrap" ref={repoContainerRef}>
          <button
            type="button"
            className="topbar__select"
            aria-label="Select repository"
            aria-expanded={repoOpen}
            aria-haspopup="listbox"
            onClick={() => setRepoOpen(!repoOpen)}
          >
            <span className="topbar__select-text">{currentRepoName}</span>
            <span className="topbar__select-caret" aria-hidden="true">
              &#9662;
            </span>
          </button>

          {repoOpen && (
            <div
              className="topbar__dropdown"
              role="listbox"
              aria-label="Repository list"
            >
              {reposLoading ? (
                <div className="topbar__dropdown-status" role="status">
                  Loading repositories\u2026
                </div>
              ) : !repoList || repoList.repositories.length === 0 ? (
                <div className="topbar__dropdown-status" role="status">
                  No repositories available
                </div>
              ) : (
                <ul className="topbar__dropdown-list">
                  <li
                    className={`topbar__dropdown-item${
                      !currentProjectId ? " topbar__dropdown-item--active" : ""
                    }`}
                    role="option"
                    aria-selected={!currentProjectId}
                    tabIndex={0}
                    onClick={() => handleRepoSelect(null)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleRepoSelect(null);
                    }}
                  >
                    All repositories
                  </li>
                  {repoList.repositories.map((repo) => (
                    <li
                      key={repo.project_id}
                      className={`topbar__dropdown-item${
                        currentProjectId === repo.project_id
                          ? " topbar__dropdown-item--active"
                          : ""
                      }`}
                      role="option"
                      aria-selected={currentProjectId === repo.project_id}
                      tabIndex={0}
                      onClick={() => handleRepoSelect(repo.project_id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleRepoSelect(repo.project_id);
                      }}
                    >
                      {repo.name}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* ── Notifications ───────────────────────────────────── */}
        <div className="topbar__notif-wrap" ref={notifContainerRef}>
          <IconButton
            label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
            onClick={() => setNotifOpen(!notifOpen)}
          >
            <BellIcon />
            {unreadCount > 0 && (
              <span className="topbar__notif-badge" aria-hidden="true">
                {unreadCount > 99 ? "99+" : unreadCount}
              </span>
            )}
          </IconButton>

          {notifOpen && (
            <div className="topbar__dropdown topbar__notif-panel">
              <div className="topbar__notif-header">
                <span className="topbar__notif-title">Notifications</span>
                {unreadCount > 0 && (
                  <button
                    type="button"
                    className="topbar__notif-mark-read"
                    onClick={() => markAllRead()}
                  >
                    Mark all read
                  </button>
                )}
              </div>
              {notifsLoading ? (
                <div className="topbar__dropdown-status" role="status">
                  Loading notifications\u2026
                </div>
              ) : notifications.length === 0 ? (
                <div className="topbar__dropdown-status" role="status">
                  No notifications
                </div>
              ) : (
                <ul className="topbar__notif-list">
                  {notifications.slice(0, 20).map((notif) => (
                    <li
                      key={notif.id}
                      className={`topbar__notif-item${
                        !notif.read ? " topbar__notif-item--unread" : ""
                      }`}
                      tabIndex={0}
                      onClick={() => handleNotifClick(notif)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") handleNotifClick(notif);
                      }}
                    >
                      <span className="topbar__notif-item-title">
                        {notif.title}
                      </span>
                      <span className="topbar__notif-item-message">
                        {notif.message}
                      </span>
                      <span className="topbar__notif-item-time">
                        {new Date(notif.created_at).toLocaleDateString()}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>

        {/* ── Theme Toggle ────────────────────────────────────── */}
        <IconButton
          label={
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
          }
          onClick={toggleTheme}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </IconButton>

        {/* ── Profile ─────────────────────────────────────────── */}
        <button
          type="button"
          className="topbar__profile"
          aria-label="Profile"
          onClick={() => navigate("/profile")}
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
