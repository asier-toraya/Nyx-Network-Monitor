import { startTransition, useEffect, useMemo, useState } from "react";
import { ActivityHistoryPanel } from "./components/ActivityHistoryPanel";
import { AlertList } from "./components/AlertList";
import { CommandOutputModal } from "./components/CommandOutputModal";
import { ConnectionTable } from "./components/ConnectionTable";
import { DetailPanel } from "./components/DetailPanel";
import { EstablishedConnectionsPanel } from "./components/EstablishedConnectionsPanel";
import { SettingsPanel } from "./components/SettingsPanel";
import { SummaryCard } from "./components/SummaryCard";
import { TrustedRulesPanel } from "./components/TrustedRulesPanel";
import {
  createAllowRule,
  deleteAllowRule,
  dismissAlert,
  getAlertDetails,
  getAlerts,
  getEstablishedConnections,
  getLiveConnections,
  getRecentActivity,
  getSettings,
  listAllowRules,
  subscribeConnectionEvents,
  updateAllowRule,
  updateSettings
} from "./lib/tauri";
import type {
  ActivityEvent,
  AlertRecord,
  AllowRule,
  AppSettings,
  CommandExecutionResult,
  ConnectionEvent,
  RiskLevel,
  SummaryStats
} from "./types";

type AppTab =
  | "dashboard"
  | "alerts"
  | "established"
  | "live"
  | "history"
  | "rules"
  | "settings";
type ConnectionFilter = RiskLevel | "all";
type SelectedConnectionSource = "live" | "history" | null;
type MonitorStateFilter =
  | "all"
  | "active"
  | "passive"
  | "established"
  | "listening"
  | "closed";
type MonitorDirectionFilter =
  | "all"
  | "incoming"
  | "outgoing"
  | "listening"
  | "closing"
  | "closed";
type MonitorSort = "risk" | "recent" | "process" | "remote" | "local" | "score" | "confidence";

const ACTIVITY_LIMIT = 200;
const RECONCILE_INTERVAL_MS = 30_000;

function computeSummary(connections: ConnectionEvent[]): SummaryStats {
  return connections.reduce(
    (summary, connection) => {
      summary.total += 1;
      summary[connection.riskLevel] += 1;
      return summary;
    },
    { safe: 0, unknown: 0, suspicious: 0, total: 0 }
  );
}

function sortConnections(connections: ConnectionEvent[]) {
  const weights = { suspicious: 3, unknown: 2, safe: 1 };
  const activityWeight = (connection: ConnectionEvent) => {
    const normalizedState = connection.state.replace(/[^a-z0-9]/gi, "").toLowerCase();

    if (normalizedState === "established") {
      return 3;
    }

    if (normalizedState === "synsent") {
      return 2;
    }

    if (connection.direction === "listening") {
      return 1;
    }

    if (normalizedState === "closewait" || normalizedState === "timewait") {
      return 0;
    }

    return 1;
  };

  return [...connections].sort((left, right) => {
    const score = weights[right.riskLevel] - weights[left.riskLevel];
    if (score !== 0) {
      return score;
    }

    const activityScore = activityWeight(right) - activityWeight(left);
    if (activityScore !== 0) {
      return activityScore;
    }

    return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
  });
}

function mergeConnections(
  current: ConnectionEvent[],
  incoming: ConnectionEvent[],
  removedIds: string[] = []
): ConnectionEvent[] {
  const next = new Map(current.map((entry) => [entry.id, entry]));
  removedIds.forEach((id) => next.delete(id));
  incoming.forEach((entry) => {
    next.set(entry.id, entry);
  });
  return sortConnections(Array.from(next.values()));
}

function mergeAlerts(current: AlertRecord[], incoming: AlertRecord[]): AlertRecord[] {
  const next = new Map(current.map((entry) => [entry.id, entry]));
  incoming.forEach((entry) => {
    next.set(entry.id, entry);
  });

  return Array.from(next.values())
    .sort(
      (left, right) =>
        new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
    )
    .slice(0, 100);
}

function mergeActivity(current: ActivityEvent[], incoming: ActivityEvent[]): ActivityEvent[] {
  const next = new Map(current.map((entry) => [entry.id, entry]));
  incoming.forEach((entry) => {
    next.set(entry.id, entry);
  });

  return Array.from(next.values())
    .sort(
      (left, right) =>
        new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    )
    .slice(0, ACTIVITY_LIMIT);
}

function normalizeQuery(value: string) {
  return value.trim().toLowerCase();
}

function connectionSearchTerms(connection: ConnectionEvent) {
  return [
    connection.id,
    connection.process.name,
    connection.process.exePath,
    connection.process.signer,
    connection.process.publisher,
    connection.process.user,
    connection.process.parentName,
    connection.process.sha256,
    connection.process.hostedServices.join(" "),
    connection.pid.toString(),
    connection.localAddress,
    connection.localPort.toString(),
    connection.remoteAddress,
    connection.remotePort?.toString(),
    connection.protocol,
    connection.direction,
    connection.state,
    connection.riskLevel,
    connection.destination?.scope,
    connection.destination?.hostname,
    connection.destination?.organization,
    connection.destination?.asn,
    connection.destination?.domain,
    connection.destination?.country,
    connection.destination?.source,
    connection.reputation?.summary,
    connection.reasons.map((reason) => `${reason.code} ${reason.message}`).join(" ")
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function matchesConnectionQuery(connection: ConnectionEvent, query: string) {
  const normalizedQuery = normalizeQuery(query);
  if (!normalizedQuery) {
    return true;
  }
  return connectionSearchTerms(connection).includes(normalizedQuery);
}

function matchesAlertQuery(alert: AlertRecord, query: string) {
  const normalizedQuery = normalizeQuery(query);
  if (!normalizedQuery) {
    return true;
  }

  return [
    alert.recommendedAction,
    alert.riskLevel,
    alert.connection?.process.name,
    alert.connection?.remoteAddress,
    alert.connection?.localAddress,
    alert.connection?.pid.toString(),
    alert.connection?.destination?.hostname,
    alert.connection?.destination?.organization,
    alert.connection?.destination?.asn,
    alert.connection?.destination?.domain,
    alert.reasons.map((reason) => `${reason.code} ${reason.message}`).join(" ")
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
}

function matchesAlertStateFilter(alert: AlertRecord, filter: MonitorStateFilter) {
  if (filter === "all") {
    return true;
  }

  return alert.connection ? matchesStateFilter(alert.connection, filter) : false;
}

function matchesAlertDirectionFilter(alert: AlertRecord, filter: MonitorDirectionFilter) {
  if (filter === "all") {
    return true;
  }

  return alert.connection ? matchesDirectionFilter(alert.connection, filter) : false;
}

function matchesActivityQuery(event: ActivityEvent, query: string) {
  const normalizedQuery = normalizeQuery(query);
  if (!normalizedQuery) {
    return true;
  }

  return `${event.changeType} ${connectionSearchTerms(event.connection)}`
    .toLowerCase()
    .includes(normalizedQuery);
}

function filterLabel(value: ConnectionFilter) {
  if (value === "all") {
    return "All connections";
  }
  if (value === "safe") {
    return "Secure";
  }
  if (value === "unknown") {
    return "Unidentified";
  }
  return "Suspicious";
}

function normalizeState(state: string) {
  return state.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function isEstablishedTcp(connection: ConnectionEvent) {
  return connection.protocol.toLowerCase() === "tcp" && normalizeState(connection.state) === "established";
}

function isPassiveConnection(connection: ConnectionEvent) {
  const normalizedState = normalizeState(connection.state);
  return (
    connection.direction === "listening" ||
    normalizedState === "timewait" ||
    normalizedState === "closewait"
  );
}

function matchesStateFilter(connection: ConnectionEvent, filter: MonitorStateFilter) {
  if (filter === "all") {
    return true;
  }

  const state = normalizeState(connection.state);

  if (filter === "active") {
    return !isPassiveConnection(connection);
  }

  if (filter === "passive") {
    return isPassiveConnection(connection);
  }

  if (filter === "established") {
    return state === "established";
  }

  if (filter === "listening") {
    return connection.direction === "listening";
  }

  if (filter === "closed") {
    return state === "timewait" || state === "closewait";
  }

  return true;
}

function matchesDirectionFilter(connection: ConnectionEvent, filter: MonitorDirectionFilter) {
  if (filter === "all") {
    return true;
  }

  return connection.direction === filter;
}

function endpointLabel(connection: ConnectionEvent, mode: "local" | "remote") {
  if (mode === "local") {
    return `${connection.localAddress}:${connection.localPort}`;
  }

  return connection.remoteAddress && connection.remotePort
    ? `${connection.remoteAddress}:${connection.remotePort}`
    : "";
}

function alertEndpointLabel(alert: AlertRecord, mode: "local" | "remote") {
  if (!alert.connection) {
    return "";
  }

  return endpointLabel(alert.connection, mode);
}

function sortConnectionsByMode(connections: ConnectionEvent[], sortMode: MonitorSort) {
  if (sortMode === "risk") {
    return sortConnections(connections);
  }

  const sorted = [...connections];

  sorted.sort((left, right) => {
    if (sortMode === "recent") {
      return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
    }

    if (sortMode === "process") {
      return left.process.name.localeCompare(right.process.name) || left.pid - right.pid;
    }

    if (sortMode === "remote") {
      return (
        endpointLabel(left, "remote").localeCompare(endpointLabel(right, "remote")) ||
        right.score - left.score
      );
    }

    if (sortMode === "local") {
      return (
        endpointLabel(left, "local").localeCompare(endpointLabel(right, "local")) ||
        right.score - left.score
      );
    }

    if (sortMode === "score") {
      return right.score - left.score || new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
    }

    return (
      right.confidence - left.confidence ||
      new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    );
  });

  return sorted;
}

function sortAlertsByMode(alerts: AlertRecord[], sortMode: MonitorSort) {
  const weights = { suspicious: 3, unknown: 2, safe: 1 };
  const sorted = [...alerts];

  sorted.sort((left, right) => {
    if (sortMode === "risk") {
      return (
        weights[right.riskLevel] - weights[left.riskLevel] ||
        right.score - left.score ||
        new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
      );
    }

    if (sortMode === "recent") {
      return new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime();
    }

    if (sortMode === "process") {
      return (
        (left.connection?.process.name ?? "Unknown process").localeCompare(
          right.connection?.process.name ?? "Unknown process"
        ) ||
        (left.connection?.pid ?? 0) - (right.connection?.pid ?? 0)
      );
    }

    if (sortMode === "remote") {
      return (
        alertEndpointLabel(left, "remote").localeCompare(alertEndpointLabel(right, "remote")) ||
        right.score - left.score
      );
    }

    if (sortMode === "local") {
      return (
        alertEndpointLabel(left, "local").localeCompare(alertEndpointLabel(right, "local")) ||
        right.score - left.score
      );
    }

    if (sortMode === "score") {
      return right.score - left.score || new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime();
    }

    return (
      right.confidence - left.confidence ||
      new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
    );
  });

  return sorted;
}

function tabMeta(tab: AppTab) {
  if (tab === "dashboard") {
    return {
      eyebrow: "Operations",
      title: "Dashboard",
      copy: "Review current sockets, live investigations and active TCP sessions."
    };
  }

  if (tab === "alerts") {
    return {
      eyebrow: "Operations",
      title: "Alerts",
      copy: "Focus on active investigations and alert-driven triage without the dashboard split."
    };
  }

  if (tab === "established") {
    return {
      eyebrow: "Operations",
      title: "Established connections",
      copy: "Inspect active TCP sessions in a dedicated full-height view."
    };
  }

  if (tab === "live") {
    return {
      eyebrow: "Operations",
      title: "Live connections",
      copy: "Review the full live socket inventory with more room for the connection table."
    };
  }

  if (tab === "history") {
    return {
      eyebrow: "History",
      title: "Activity history",
      copy: "Inspect recent socket opens, updates and closures captured by the collector."
    };
  }

  if (tab === "rules") {
    return {
      eyebrow: "Trust",
      title: "Trusted rules",
      copy: "Review analyst-approved process, target and pinning exceptions."
    };
  }

  return {
    eyebrow: "Configuration",
    title: "Engine settings",
    copy: "Configure collection, learning and trust policy."
  };
}

export default function App() {
  const [connections, setConnections] = useState<ConnectionEvent[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [allowRules, setAllowRules] = useState<AllowRule[]>([]);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [selectedConnection, setSelectedConnection] = useState<ConnectionEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [selectedConnectionSource, setSelectedConnectionSource] =
    useState<SelectedConnectionSource>(null);
  const [selectedActivityId, setSelectedActivityId] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<AppTab>("dashboard");
  const [activeFilter, setActiveFilter] = useState<ConnectionFilter>("all");
  const [monitorQuery, setMonitorQuery] = useState("");
  const [historyQuery, setHistoryQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<MonitorStateFilter>("all");
  const [directionFilter, setDirectionFilter] = useState<MonitorDirectionFilter>("all");
  const [sortMode, setSortMode] = useState<MonitorSort>("risk");
  const [establishedResult, setEstablishedResult] = useState<CommandExecutionResult | null>(null);
  const [establishedOpen, setEstablishedOpen] = useState(false);
  const [establishedLoading, setEstablishedLoading] = useState(false);
  const [establishedError, setEstablishedError] = useState<string | null>(null);
  const currentTab = tabMeta(activeTab);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    async function bootstrap() {
      try {
        unlisten = await subscribeConnectionEvents((update) => {
          startTransition(() => {
            setConnections((current) =>
              mergeConnections(
                current,
                update.connections,
                update.removedConnectionIds
              )
            );
            setAlerts((current) => mergeAlerts(current, update.alerts));
            setActivity((current) => mergeActivity(current, update.activity));
            setLastRefresh(update.collectedAt);
          });
        });

        const [live, alertRows, rules, savedSettings, recentActivity] = await Promise.all([
          getLiveConnections(),
          getAlerts({ statuses: ["open", "new"], limit: 100 }),
          listAllowRules(),
          getSettings(),
          getRecentActivity(ACTIVITY_LIMIT)
        ]);

        if (disposed) {
          return;
        }

        startTransition(() => {
          setConnections((current) => mergeConnections(live, current));
          setAlerts((current) => mergeAlerts(alertRows, current));
          setActivity((current) => mergeActivity(recentActivity, current));
          setAllowRules(rules);
          setSettings(savedSettings);
          setLastRefresh(new Date().toISOString());
        });
      } catch (cause) {
        if (!disposed) {
          setError(cause instanceof Error ? cause.message : "Failed to load app state");
        }
      }
    }

    void bootstrap();

    return () => {
      disposed = true;
      if (unlisten) {
        void unlisten();
      }
    };
  }, []);

  useEffect(() => {
    let disposed = false;

    const interval = window.setInterval(() => {
      void (async () => {
        try {
          const [live, alertRows, recentActivity] = await Promise.all([
            getLiveConnections(),
            getAlerts({ statuses: ["open", "new"], limit: 100 }),
            getRecentActivity(ACTIVITY_LIMIT)
          ]);

          if (disposed) {
            return;
          }

          startTransition(() => {
            setConnections(sortConnections(live));
            setAlerts(mergeAlerts([], alertRows));
            setActivity(mergeActivity([], recentActivity));
            setLastRefresh(new Date().toISOString());
          });
        } catch {
          // Keep the monitor running on the last good snapshot if reconciliation fails.
        }
      })();
    }, RECONCILE_INTERVAL_MS);

    return () => {
      disposed = true;
      window.clearInterval(interval);
    };
  }, []);

  const summary = useMemo(() => computeSummary(connections), [connections]);

  const searchedConnections = useMemo(
    () => connections.filter((connection) => matchesConnectionQuery(connection, monitorQuery)),
    [connections, monitorQuery]
  );

  const tabFilteredConnections = useMemo(() => {
    const filtered = searchedConnections.filter(
      (connection) =>
        matchesStateFilter(connection, stateFilter) &&
        matchesDirectionFilter(connection, directionFilter)
    );

    return sortConnectionsByMode(filtered, sortMode);
  }, [directionFilter, searchedConnections, sortMode, stateFilter]);

  const filteredConnections = useMemo(
    () =>
      tabFilteredConnections.filter((connection) =>
        activeFilter === "all" ? true : connection.riskLevel === activeFilter
      ),
    [activeFilter, tabFilteredConnections]
  );

  const filteredAlerts = useMemo(
    () =>
      sortAlertsByMode(
        alerts.filter(
          (alert) =>
            matchesAlertQuery(alert, monitorQuery) &&
            matchesAlertStateFilter(alert, stateFilter) &&
            matchesAlertDirectionFilter(alert, directionFilter)
        ),
        sortMode
      ),
    [alerts, directionFilter, monitorQuery, sortMode, stateFilter]
  );

  const establishedConnections = useMemo(
    () => filteredConnections.filter((connection) => isEstablishedTcp(connection)),
    [filteredConnections]
  );
  const tabEstablishedConnections = useMemo(
    () => tabFilteredConnections.filter((connection) => isEstablishedTcp(connection)),
    [tabFilteredConnections]
  );

  const historyEvents = useMemo(
    () => activity.filter((event) => matchesActivityQuery(event, historyQuery)),
    [activity, historyQuery]
  );

  useEffect(() => {
    if (!selectedConnection || selectedConnectionSource !== "live") {
      return;
    }

    const stillExists = connections.some((connection) => connection.id === selectedConnection.id);
    if (!stillExists) {
      setSelectedConnection(null);
      setSelectedAlert(null);
      setSelectedConnectionSource(null);
      setSelectedActivityId(null);
    }
  }, [connections, selectedConnection, selectedConnectionSource]);

  useEffect(() => {
    if (!selectedConnection && !establishedOpen) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        handleCloseDetails();
        setEstablishedOpen(false);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [establishedOpen, selectedConnection]);

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
    const created = await createAllowRule({
      label: `${connection.process.name} -> ${connection.remoteAddress ?? "listener"}`,
      enabled: true,
      processName: connection.process.name,
      signer: connection.process.signer,
      exePath: connection.process.exePath,
      sha256: connection.process.sha256,
      remotePattern: connection.remoteAddress,
      port: connection.remotePort ?? connection.localPort,
      protocol: connection.protocol,
      direction: connection.direction,
      notes: `Created from connection inspector on ${new Date().toLocaleString()}`
    });
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
      patch.remotePattern = changes.remotePattern?.trim()
        ? changes.remotePattern.trim()
        : null;
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

  async function handleOpenEstablishedConnections() {
    setEstablishedOpen(true);
    if (establishedLoading) {
      return;
    }
    await handleRefreshEstablishedConnections();
  }

  async function handleRefreshEstablishedConnections() {
    setEstablishedLoading(true);
    setEstablishedError(null);
    try {
      const result = await getEstablishedConnections();
      setEstablishedResult(result);
    } catch (cause) {
      setEstablishedError(
        cause instanceof Error ? cause.message : "Failed to fetch established connections"
      );
    } finally {
      setEstablishedLoading(false);
    }
  }

  function handleCloseDetails() {
    setSelectedConnection(null);
    setSelectedAlert(null);
    setSelectedConnectionSource(null);
    setSelectedActivityId(null);
  }

  function toggleFilter(next: ConnectionFilter) {
    setActiveTab("dashboard");
    setActiveFilter((current) => (current === next ? "all" : next));
  }

  function renderConnectionControls(searchPlaceholder: string) {
    return (
      <section className="monitor-controls">
        <label className="monitor-controls__field">
          <span className="detail-label">State</span>
          <select
            value={stateFilter}
            onChange={(event) => setStateFilter(event.target.value as MonitorStateFilter)}
          >
            <option value="all">All states</option>
            <option value="active">Active</option>
            <option value="passive">Passive</option>
            <option value="established">Established</option>
            <option value="listening">Listening</option>
            <option value="closed">Closed / cleanup</option>
          </select>
        </label>
        <label className="monitor-controls__field">
          <span className="detail-label">Direction</span>
          <select
            value={directionFilter}
            onChange={(event) =>
              setDirectionFilter(event.target.value as MonitorDirectionFilter)
            }
          >
            <option value="all">All directions</option>
            <option value="incoming">Incoming</option>
            <option value="outgoing">Outgoing</option>
            <option value="listening">Listening</option>
            <option value="closing">Closing</option>
            <option value="closed">Closed</option>
          </select>
        </label>
        <label className="monitor-controls__field">
          <span className="detail-label">Sort</span>
          <select
            value={sortMode}
            onChange={(event) => setSortMode(event.target.value as MonitorSort)}
          >
            <option value="risk">Highest risk</option>
            <option value="recent">Most recent</option>
            <option value="process">Process</option>
            <option value="remote">Remote endpoint</option>
            <option value="local">Local endpoint</option>
            <option value="score">Risk score</option>
            <option value="confidence">Confidence</option>
          </select>
        </label>
        <label className="monitor-controls__field monitor-controls__field--search">
          <span className="detail-label">Search</span>
          <input
            type="search"
            value={monitorQuery}
            onChange={(event) => setMonitorQuery(event.target.value)}
            placeholder={searchPlaceholder}
          />
        </label>
      </section>
    );
  }

  return (
    <main className="app-shell">
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <p className="sidebar-brand__eyebrow">Sentinel Desk</p>
          <strong>Network security</strong>
          <span>Desktop monitor</span>
        </div>

        <nav className="app-nav" aria-label="Application sections">
          <button
            type="button"
            className={`app-nav__button ${activeTab === "dashboard" ? "is-active" : ""}`}
            onClick={() => setActiveTab("dashboard")}
          >
            Dashboard
          </button>
          <button
            type="button"
            className={`app-nav__button app-nav__button--monitoring ${activeTab === "alerts" ? "is-active" : ""}`}
            onClick={() => setActiveTab("alerts")}
          >
            Alerts
          </button>
          <button
            type="button"
            className={`app-nav__button app-nav__button--monitoring ${activeTab === "established" ? "is-active" : ""}`}
            onClick={() => setActiveTab("established")}
          >
            Established connections
          </button>
          <button
            type="button"
            className={`app-nav__button app-nav__button--monitoring ${activeTab === "live" ? "is-active" : ""}`}
            onClick={() => setActiveTab("live")}
          >
            Live connections
          </button>
          <button
            type="button"
            className={`app-nav__button ${activeTab === "history" ? "is-active" : ""}`}
            onClick={() => setActiveTab("history")}
          >
            Activity history
          </button>
          <button
            type="button"
            className={`app-nav__button ${activeTab === "rules" ? "is-active" : ""}`}
            onClick={() => setActiveTab("rules")}
          >
            Trusted rules
          </button>
          <button
            type="button"
            className={`app-nav__button ${activeTab === "settings" ? "is-active" : ""}`}
            onClick={() => setActiveTab("settings")}
          >
            Engine settings
          </button>
        </nav>

        <div className="sidebar-status">
          <span className="status-dot" />
          <div>
            <strong>{lastRefresh ? "Collector online" : "Starting collector"}</strong>
            <span>
              {lastRefresh
                ? `Updated ${new Date(lastRefresh).toLocaleTimeString()}`
                : "Waiting for first snapshot"}
            </span>
            <span>{summary.total} current sockets</span>
            <span>{activity.length} recent activity events</span>
          </div>
        </div>
      </aside>

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

          {activeTab === "history" ? (
            <div className="page-header__aside page-header__aside--search">
              <label className="page-search">
                <span className="sr-only">Search activity history</span>
                <input
                  type="search"
                  value={historyQuery}
                  onChange={(event) => setHistoryQuery(event.target.value)}
                  placeholder="Search process, change type, IP, port or reason"
                />
              </label>
              <div className="page-header__meta">
                <span className="page-header__meta-label">Visible</span>
                <strong>{`${historyEvents.length} of ${activity.length}`}</strong>
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

            {renderConnectionControls("Search process, PID, IP, port or reason")}

            <section className="monitor-workspace">
              <AlertList
                alerts={filteredAlerts}
                selectedAlertId={selectedAlert?.id ?? null}
                onSelect={handleSelectAlert}
              />
              <EstablishedConnectionsPanel
                connections={establishedConnections}
                selectedId={
                  selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null
                }
                onSelect={handleSelectLiveConnection}
                onOpenModal={() => void handleOpenEstablishedConnections()}
              />
              <ConnectionTable
                connections={filteredConnections}
                selectedId={
                  selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null
                }
                onSelect={handleSelectLiveConnection}
              />
            </section>
          </>
        ) : null}

        {activeTab === "history" ? (
          <ActivityHistoryPanel
            events={historyEvents}
            selectedId={selectedActivityId}
            onSelect={handleSelectHistoryEvent}
          />
        ) : null}

        {activeTab === "alerts" ? (
          <>
            {renderConnectionControls("Search process, PID, IP, port or alert reason")}
            <AlertList
              alerts={filteredAlerts}
              selectedAlertId={selectedAlert?.id ?? null}
              onSelect={handleSelectAlert}
              fullHeight
            />
          </>
        ) : null}

        {activeTab === "established" ? (
          <>
            {renderConnectionControls("Search process, PID, IP, port or reason")}
            <EstablishedConnectionsPanel
              connections={tabEstablishedConnections}
              selectedId={
                selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null
              }
              onSelect={handleSelectLiveConnection}
              onOpenModal={() => void handleOpenEstablishedConnections()}
              fullHeight
            />
          </>
        ) : null}

        {activeTab === "live" ? (
          <>
            {renderConnectionControls("Search process, PID, IP, port or reason")}
            <ConnectionTable
              connections={tabFilteredConnections}
              selectedId={
                selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null
              }
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
            onClose={() => setEstablishedOpen(false)}
            onRefresh={() => void handleRefreshEstablishedConnections()}
          />
        ) : null}
      </section>
    </main>
  );
}
