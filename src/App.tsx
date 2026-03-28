import { useState } from "react";
import { AlertList } from "./components/AlertList";
import { AppSidebar } from "./components/AppSidebar";
import { CommandOutputModal } from "./components/CommandOutputModal";
import { ConnectionControls } from "./components/ConnectionControls";
import { ConnectionTable } from "./components/ConnectionTable";
import { DashboardView } from "./components/DashboardView";
import { DetailPanel } from "./components/DetailPanel";
import { EstablishedConnectionsPanel } from "./components/EstablishedConnectionsPanel";
import { HistoryView } from "./components/HistoryView";
import { PageHeader } from "./components/PageHeader";
import { SettingsPanel } from "./components/SettingsPanel";
import { TrustedRulesPanel } from "./components/TrustedRulesPanel";
import { useConnectionSelection } from "./hooks/useConnectionSelection";
import { useEstablishedReport } from "./hooks/useEstablishedReport";
import { useMonitorData } from "./hooks/useMonitorData";
import { useMonitorFilters } from "./hooks/useMonitorFilters";
import { useThemeMode } from "./hooks/useThemeMode";
import {
  buildProcessAllowRule,
  buildStrictAllowRule,
  type AppTab,
  type ConnectionFilter
} from "./lib/monitoring";
import {
  createAllowRule,
  deleteAllowRule,
  dismissAlert,
  updateAllowRule,
  updateSettings
} from "./lib/tauri";
import type { AlertRecord, AllowRule, AppSettings, ConnectionEvent } from "./types";

export default function App() {
  const [activeTab, setActiveTab] = useState<AppTab>("dashboard");

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
  const {
    selectedConnection,
    selectedAlert,
    selectedActivityId,
    selectedLiveConnectionId,
    handleCloseDetails,
    handleSelectLiveConnection,
    handleSelectHistoryEvent,
    handleSelectAlert,
    handleDismissedAlert
  } = useConnectionSelection({
    alerts,
    liveConnections: connections,
    escapeActive: establishedOpen,
    onEscape: handleCloseEstablishedConnections
  });

  const monitorControls = {
    riskFilter: activeFilter,
    onRiskFilterChange: setActiveFilter,
    stateFilter,
    onStateFilterChange: setStateFilter,
    directionFilter,
    onDirectionFilterChange: setDirectionFilter,
    sortMode,
    onSortModeChange: setSortMode,
    query: monitorQuery,
    onQueryChange: setMonitorQuery
  };

  function toggleFilter(next: ConnectionFilter) {
    setActiveTab("dashboard");
    setActiveFilter((current) => (current === next ? "all" : next));
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
    handleDismissedAlert(alert.id);
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
        <PageHeader activeTab={activeTab} activeFilter={activeFilter} />

        {error ? <div className="banner-error">{error}</div> : null}

        {activeTab === "dashboard" ? (
          <DashboardView
            summary={summary}
            activeFilter={activeFilter}
            onToggleSummaryFilter={toggleFilter}
            onRiskFilterChange={setActiveFilter}
            onClearFilter={() => setActiveFilter("all")}
            monitorQuery={monitorQuery}
            onMonitorQueryChange={setMonitorQuery}
            stateFilter={stateFilter}
            onStateFilterChange={setStateFilter}
            directionFilter={directionFilter}
            onDirectionFilterChange={setDirectionFilter}
            sortMode={sortMode}
            onSortModeChange={setSortMode}
            alerts={filteredAlerts}
            selectedAlertId={selectedAlert?.id ?? null}
            onSelectAlert={handleSelectAlert}
            establishedConnections={establishedConnections}
            selectedConnectionId={selectedLiveConnectionId}
            onSelectConnection={handleSelectLiveConnection}
            onOpenEstablishedModal={() => void handleOpenEstablishedConnections()}
            liveConnections={filteredConnections}
          />
        ) : null}

        {activeTab === "history" ? (
          <HistoryView
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
            events={historyEvents}
            selectedId={selectedActivityId}
            onSelect={handleSelectHistoryEvent}
          />
        ) : null}

        {activeTab === "alerts" ? (
          <>
            <ConnectionControls
              {...monitorControls}
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
              {...monitorControls}
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
              {...monitorControls}
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
