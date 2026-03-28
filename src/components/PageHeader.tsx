import { filterLabel, tabMeta, type AppTab, type ConnectionFilter } from "../lib/monitoring";

interface PageHeaderProps {
  activeTab: AppTab;
  activeFilter: ConnectionFilter;
}

export function PageHeader({ activeTab, activeFilter }: PageHeaderProps) {
  const currentTab = tabMeta(activeTab);

  return (
    <header className="page-header">
      <div>
        <p className="page-header__eyebrow">{currentTab.eyebrow}</p>
        <h1>{currentTab.title}</h1>
        <p className="page-header__copy">{currentTab.copy}</p>
      </div>

      {activeTab === "dashboard" ? (
        <div className="page-header__aside">
          <div className="page-header__meta">
            <span className="page-header__meta-label">Scope</span>
            <strong>{filterLabel(activeFilter)}</strong>
          </div>
        </div>
      ) : null}
    </header>
  );
}
