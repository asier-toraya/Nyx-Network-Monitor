import type { AppTab, ThemeMode } from "../lib/monitoring";

interface AppSidebarProps {
  activeTab: AppTab;
  onSelectTab: (tab: AppTab) => void;
  themeMode: ThemeMode;
  onThemeChange: (mode: ThemeMode) => void;
  lastRefresh: string | null;
  totalSockets: number;
  activityCount: number;
}

const NAV_ITEMS: Array<{
  id: AppTab;
  label: string;
  monitoring?: boolean;
}> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "alerts", label: "Alerts", monitoring: true },
  { id: "established", label: "Established connections", monitoring: true },
  { id: "live", label: "Live connections", monitoring: true },
  { id: "history", label: "Activity history" },
  { id: "rules", label: "Trusted rules" },
  { id: "settings", label: "Engine settings" }
];

export function AppSidebar({
  activeTab,
  onSelectTab,
  themeMode,
  onThemeChange,
  lastRefresh,
  totalSockets,
  activityCount
}: AppSidebarProps) {
  return (
    <aside className="app-sidebar">
      <div className="sidebar-brand">
        <p className="sidebar-brand__eyebrow">Sentinel Desk</p>
        <strong>Network security</strong>
        <span>Desktop monitor</span>
      </div>

      <nav className="app-nav" aria-label="Application sections">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={`app-nav__button ${item.monitoring ? "app-nav__button--monitoring " : ""}${activeTab === item.id ? "is-active" : ""}`.trim()}
            onClick={() => onSelectTab(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <section className="sidebar-theme" aria-label="Appearance">
        <div className="sidebar-theme__header">
          <div>
            <p className="sidebar-theme__label">Appearance</p>
            <span className="sidebar-theme__copy">
              Switch the interface for bright or low-light work.
            </span>
          </div>
          <span className="sidebar-theme__value">
            {themeMode === "dark" ? "Dark mode" : "Light mode"}
          </span>
        </div>

        <div className="theme-toggle" role="group" aria-label="Theme mode">
          <button
            type="button"
            className={`theme-toggle__button ${themeMode === "light" ? "is-active" : ""}`}
            onClick={() => onThemeChange("light")}
            aria-pressed={themeMode === "light"}
          >
            Light
          </button>
          <button
            type="button"
            className={`theme-toggle__button ${themeMode === "dark" ? "is-active" : ""}`}
            onClick={() => onThemeChange("dark")}
            aria-pressed={themeMode === "dark"}
          >
            Dark
          </button>
        </div>
      </section>

      <div className="sidebar-status">
        <span className="status-dot" />
        <div>
          <strong>{lastRefresh ? "Collector online" : "Starting collector"}</strong>
          <span>
            {lastRefresh
              ? `Updated ${new Date(lastRefresh).toLocaleTimeString()}`
              : "Waiting for first snapshot"}
          </span>
          <span>{totalSockets} current sockets</span>
          <span>{activityCount} recent activity events</span>
        </div>
      </div>
    </aside>
  );
}
