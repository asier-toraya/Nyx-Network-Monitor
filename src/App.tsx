import { useEffect, useState } from "react";
import { ActivityHistoryPanel } from "./components/ActivityHistoryPanel";
import { AlertList } from "./components/AlertList";
import { AppSidebar } from "./components/AppSidebar";
import { CommandOutputModal } from "./components/CommandOutputModal";
import { ConnectionControls } from "./components/ConnectionControls";
import { ConnectionTable } from "./components/ConnectionTable";
import { DetailPanel } from "./components/DetailPanel";
import { EstablishedConnectionsPanel } from "./components/EstablishedConnectionsPanel";
import { HistoryControls } from "./components/HistoryControls";
import { SettingsPanel } from "./components/SettingsPanel";
import { SummaryCard } from "./components/SummaryCard";
import { TrustedRulesPanel } from "./components/TrustedRulesPanel";
import { useEstablishedReport } from "./hooks/useEstablishedReport";
import { useMonitorData } from "./hooks/useMonitorData";
import { useMonitorFilters } from "./hooks/useMonitorFilters";
import { useThemeMode } from "./hooks/useThemeMode";
import {
  buildProcessAllowRule,
  buildStrictAllowRule,
  filterLabel,
  tabMeta,
  type AppTab,
  type ConnectionFilter,
  type SelectedConnectionSource
} from "./lib/monitoring";
import {
  createAllowRule,
  deleteAllowRule,
  dismissAlert,
  getAlertDetails,
  updateAllowRule,
  updateSettings
} from "./lib/tauri";
import type {
  ActivityEvent,
  AlertRecord,
  AllowRule,
  AppSettings,
  ConnectionEvent
} from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState<AppTab>("dashboard");
  const [selectedConnection, setSelectedConnection] = useState<ConnectionEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [selectedConnectionSource, setSelectedConnectionSource] =
    useState<SelectedConnectionSource>(null);
  const [selectedActivityId, setSelectedActivityId] = useState<string | null>(null);

  const { themeMode, setThemeMode } = useThemeMode();
  const {
    connections,
    alerts,
    activity,
    allowRules,
    settings,
    lastRefresh,
    error,
    setAlerts,
    setAllowRules,
    setSettings
  } = useMonitorData();
  const {
    summary,
    activeFilter,
    setActiveFilter,
    monitorQuery,
    setMonitorQuery,
    historyQuery,
    setHistoryQuery,
    stateFilter,
    setStateFilter,
    directionFilter,
    setDirectionFilter,
    sortMode,
    setSortMode,
    historyStateFilter,
    setHistoryStateFilter,
    historyDirectionFilter,
    setHistoryDirectionFilter,
    historyRiskFilter,
    setHistoryRiskFilter,
    historySortMode,
    setHistorySortMode,
    filteredConnections,
    filteredAlerts,
    tabFilteredAlerts,
    tabFilteredConnections,
    establishedConnections,
    tabEstablishedConnections,
    historyEvents
  } = useMonitorFilters(connections, alerts, activity);
  const {
    establishedResult,
    establishedOpen,
    establishedLoading,
    establishedError,
    handleRefreshEstablishedConnections,
    handleOpenEstablishedConnections,
    handleCloseEstablishedConnections
  } = useEstablishedReport();

  const currentTab = tabMeta(activeTab);
  const selectedLiveConnectionId =
    selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null;

  useEffect(() => {
    if (!selectedConnection || selectedConnectionSource !== "live") {
      return;
    }

    const stillExists = connections.some((connection) => connection.id === selectedConnection.id);
    if (!stillExists) {
      clearSelection();
    }
  }, [connections, selectedConnection, selectedConnectionSource]);

  useEffect(() => {
    if (!selectedConnection && !establishedOpen) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        handleCloseDetails();
        handleCloseEstablishedConnections();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [establishedOpen, selectedConnection]);

  function clearSelection() {
    setSelectedConnection(null);
    setSelectedAlert(null);
    setSelectedConnectionSource(null);
    setSelectedActivityId(null);
  }

  function handleCloseDetails() {
    clearSelection();
  }

  function handleSelectLiveConnection(connection: ConnectionEvent) {
    setSelectedConnection(connection);
    setSelectedConnectionSource("live");
    setSelectedActivityId(null);
    const alert = alerts.find((entry) => entry.connectionEventId === connection.id) ?? null;
    setSelectedAlert(alert);
  }

  function handleSelectHistoryEvent(event: ActivityEvent) {
    setSelectedConnection(event.connection);
    setSelectedConnectionSource("history");
    setSelectedActivityId(event.id);
    const alert = alerts.find((entry) => entry.connectionEventId === event.connection.id) ?? null;
    setSelectedAlert(alert);
  }

  async function handleSelectAlert(alert: AlertRecord) {
    setSelectedAlert(alert);
    setSelectedConnectionSource("live");
    setSelectedActivityId(null);

    if (alert.connection) {
      setSelectedConnection(alert.connection);
      return;
    }

    const detailed = await getAlertDetails(alert.id);
    setSelectedAlert(detailed);
    setSelectedConnection(detailed.connection);
  }

  async function handleAllow(connection: ConnectionEvent) {
    const created = await createAllowRule(buildStrictAllowRule(connection));
    setAllowRules((current) => [created, ...current]);
  }

  async function handleAllowProcess(connection: ConnectionEvent) {
    const confirmed = window.confirm(
      `Trust the whole process "${connection.process.name}"? This will trust future connections from the same process identity, not just the current endpoint.`
    );

    if (!confirmed) {
      return;
    }

    const created = await createAllowRule(buildProcessAllowRule(connection));
    setAllowRules((current) => [created, ...current]);
  }

  async function handleUpdateRule(rule: AllowRule, changes: Partial<AllowRule>) {
    const patch: Partial<AllowRule> = {};

    if (changes.label !== undefined) {
      patch.label = changes.label.trim() || rule.label;
    }

    if (changes.enabled !== undefined) {
      patch.enabled = changes.enabled;
    }

    if (changes.processName !== undefined) {
      patch.processName = changes.processName?.trim() ? changes.processName.trim() : null;
    }

    if (changes.signer !== undefined) {
      patch.signer = changes.signer?.trim() ? changes.signer.trim() : null;
    }

    if (changes.exePath !== undefined) {
      patch.exePath = changes.exePath?.trim() ? changes.exePath.trim() : null;
    }

    if (changes.sha256 !== undefined) {
      patch.sha256 = changes.sha256?.trim() ? changes.sha256.trim() : null;
    }

    if (changes.remotePattern !== undefined) {
      patch.remotePattern = changes.remotePattern?.trim() ? changes.remotePattern.trim() : null;
    }

    if (changes.port !== undefined) {
      patch.port = changes.port;
    }

    if (changes.protocol !== undefined) {
      patch.protocol = changes.protocol?.trim() ? changes.protocol.trim() : null;
    }

    if (changes.direction !== undefined) {
      patch.direction = changes.direction?.trim() ? changes.direction.trim() : null;
    }

    if (changes.notes !== undefined) {
      patch.notes = changes.notes?.trim() ? changes.notes.trim() : null;
    }

    const updated = await updateAllowRule(rule.id, patch);

    setAllowRules((current) =>
      current.map((entry) => (entry.id === updated.id ? updated : entry))
    );
  }

  async function handleDeleteRule(rule: AllowRule) {
    const confirmed = window.confirm(`Delete trusted rule "${rule.label}"?`);
    if (!confirmed) {
      return;
    }

    await deleteAllowRule(rule.id);
    setAllowRules((current) => current.filter((entry) => entry.id !== rule.id));
  }

  async function handleDismiss(alert: AlertRecord) {
    await dismissAlert(alert.id);
    setAlerts((current) => current.filter((entry) => entry.id !== alert.id));

    if (selectedAlert?.id === alert.id) {
      setSelectedAlert(null);
    }
  }

  async function handleCopyFirewallRule(value: string) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      window.prompt("Copy the suggested firewall rule", value);
    }
  }

  async function handleSaveSettings(next: AppSettings) {
    const saved = await updateSettings(next);
    setSettings(saved);
  }

  function toggleFilter(next: ConnectionFilter) {
    setActiveTab("dashboard");
    setActiveFilter((current) => (current === next ? "all" : next));
  }

  return (
    <main className="app-shell">
      <AppSidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        themeMode={themeMode}
        onThemeChange={setThemeMode}
        lastRefresh={lastRefresh}
        totalSockets={summary.total}
        activityCount={activity.length}
      />

      <section className="app-main">
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

        {error ? <div className="banner-error">{error}</div> : null}

        {activeTab === "dashboard" ? (
          <>
            <section className="summary-grid">
              <SummaryCard
                label="Secure"
                value={summary.safe}
                tone="safe"
                detail={activeFilter === "safe" ? "Filter active" : "Allowed or learned traffic"}
                active={activeFilter === "safe"}
                onClick={() => toggleFilter("safe")}
              />
              <SummaryCard
                label="Unidentified"
                value={summary.unknown}
                tone="unknown"
                detail={activeFilter === "unknown" ? "Filter active" : "Needs analyst review"}
                active={activeFilter === "unknown"}
                onClick={() => toggleFilter("unknown")}
              />
              <SummaryCard
                label="Suspicious"
                value={summary.suspicious}
                tone="suspicious"
                detail={
                  activeFilter === "suspicious"
                    ? "Filter active"
                    : "Requires immediate review"
                }
                active={activeFilter === "suspicious"}
                onClick={() => toggleFilter("suspicious")}
              />
              <SummaryCard
                label="Total"
                value={summary.total}
                tone="neutral"
                detail={activeFilter === "all" ? "Current snapshot" : "Click to clear filter"}
                active={activeFilter === "all"}
                onClick={() => setActiveFilter("all")}
              />
            </section>

            <ConnectionControls
              riskFilter={activeFilter}
              onRiskFilterChange={setActiveFilter}
              stateFilter={stateFilter}
              onStateFilterChange={setStateFilter}
              directionFilter={directionFilter}
              onDirectionFilterChange={setDirectionFilter}
              sortMode={sortMode}
              onSortModeChange={setSortMode}
              query={monitorQuery}
              onQueryChange={setMonitorQuery}
              searchPlaceholder="Search process, PID, IP, port or reason"
            />

            <section className="monitor-workspace">
              <AlertList
                alerts={filteredAlerts}
                selectedAlertId={selectedAlert?.id ?? null}
                onSelect={handleSelectAlert}
              />
              <EstablishedConnectionsPanel
                connections={establishedConnections}
                selectedId={selectedLiveConnectionId}
                onSelect={handleSelectLiveConnection}
                onOpenModal={() => void handleOpenEstablishedConnections()}
              />
              <ConnectionTable
                connections={filteredConnections}
                selectedId={selectedLiveConnectionId}
                onSelect={handleSelectLiveConnection}
              />
            </section>
          </>
        ) : null}

        {activeTab === "history" ? (
          <>
            <HistoryControls
              riskFilter={historyRiskFilter}
              onRiskFilterChange={setHistoryRiskFilter}
              stateFilter={historyStateFilter}
              onStateFilterChange={setHistoryStateFilter}
              directionFilter={historyDirectionFilter}
              onDirectionFilterChange={setHistoryDirectionFilter}
              sortMode={historySortMode}
              onSortModeChange={setHistorySortMode}
              query={historyQuery}
              onQueryChange={setHistoryQuery}
            />
            <ActivityHistoryPanel
              events={historyEvents}
              selectedId={selectedActivityId}
              onSelect={handleSelectHistoryEvent}
            />
          </>
        ) : null}

        {activeTab === "alerts" ? (
          <>
            <ConnectionControls
              riskFilter={activeFilter}
              onRiskFilterChange={setActiveFilter}
              stateFilter={stateFilter}
              onStateFilterChange={setStateFilter}
              directionFilter={directionFilter}
              onDirectionFilterChange={setDirectionFilter}
              sortMode={sortMode}
              onSortModeChange={setSortMode}
              query={monitorQuery}
              onQueryChange={setMonitorQuery}
              searchPlaceholder="Search process, PID, IP, port or alert reason"
              showRiskFilter={false}
            />
            <AlertList
              alerts={tabFilteredAlerts}
              selectedAlertId={selectedAlert?.id ?? null}
              onSelect={handleSelectAlert}
              fullHeight
            />
          </>
        ) : null}

        {activeTab === "established" ? (
          <>
            <ConnectionControls
              riskFilter={activeFilter}
              onRiskFilterChange={setActiveFilter}
              stateFilter={stateFilter}
              onStateFilterChange={setStateFilter}
              directionFilter={directionFilter}
              onDirectionFilterChange={setDirectionFilter}
              sortMode={sortMode}
              onSortModeChange={setSortMode}
              query={monitorQuery}
              onQueryChange={setMonitorQuery}
              searchPlaceholder="Search process, PID, IP, port or reason"
            />
            <EstablishedConnectionsPanel
              connections={tabEstablishedConnections}
              selectedId={selectedLiveConnectionId}
              onSelect={handleSelectLiveConnection}
              onOpenModal={() => void handleOpenEstablishedConnections()}
              fullHeight
            />
          </>
        ) : null}

        {activeTab === "live" ? (
          <>
            <ConnectionControls
              riskFilter={activeFilter}
              onRiskFilterChange={setActiveFilter}
              stateFilter={stateFilter}
              onStateFilterChange={setStateFilter}
              directionFilter={directionFilter}
              onDirectionFilterChange={setDirectionFilter}
              sortMode={sortMode}
              onSortModeChange={setSortMode}
              query={monitorQuery}
              onQueryChange={setMonitorQuery}
              searchPlaceholder="Search process, PID, IP, port or reason"
            />
            <ConnectionTable
              connections={tabFilteredConnections}
              selectedId={selectedLiveConnectionId}
              onSelect={handleSelectLiveConnection}
              fullHeight
            />
          </>
        ) : null}

        {activeTab === "rules" ? (
          <TrustedRulesPanel
            allowRules={allowRules}
            onDelete={handleDeleteRule}
            onUpdate={handleUpdateRule}
          />
        ) : null}

        {activeTab === "settings" ? (
          <SettingsPanel settings={settings} onSave={handleSaveSettings} />
        ) : null}

        {selectedConnection ? (
          <DetailPanel
            connection={selectedConnection}
            alert={selectedAlert}
            onAllow={handleAllow}
            onAllowProcess={handleAllowProcess}
            onDismiss={handleDismiss}
            onCopyCommand={handleCopyFirewallRule}
            onClose={handleCloseDetails}
          />
        ) : null}

        {establishedOpen ? (
          <CommandOutputModal
            title="Established TCP connections (raw OS view)"
            result={establishedResult}
            loading={establishedLoading}
            error={establishedError}
            onClose={handleCloseEstablishedConnections}
            onRefresh={() => void handleRefreshEstablishedConnections()}
          />
        ) : null}
      </section>
    </main>
  );
}
