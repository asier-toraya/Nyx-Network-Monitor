import type {
  ActivityEvent,
  AlertRecord,
  AllowRule,
  ConnectionEvent,
  RiskLevel,
  SummaryStats
} from "../types";

export type AppTab =
  | "dashboard"
  | "alerts"
  | "established"
  | "live"
  | "history"
  | "rules"
  | "settings";

export type ThemeMode = "light" | "dark";
export type ConnectionFilter = RiskLevel | "all";
export type SelectedConnectionSource = "live" | "history" | null;
export type MonitorStateFilter =
  | "all"
  | "active"
  | "passive"
  | "established"
  | "listening"
  | "closed";
export type MonitorDirectionFilter =
  | "all"
  | "incoming"
  | "outgoing"
  | "listening"
  | "closing"
  | "closed";
export type MonitorSort =
  | "risk"
  | "recent"
  | "process"
  | "remote"
  | "local"
  | "score"
  | "confidence";

export const ACTIVITY_LIMIT = 200;
export const RECONCILE_INTERVAL_MS = 30_000;
export const THEME_STORAGE_KEY = "sentinel-desk-theme";

export function getInitialTheme(): ThemeMode {
  if (typeof window === "undefined") {
    return "light";
  }

  const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (storedTheme === "light" || storedTheme === "dark") {
    return storedTheme;
  }

  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function computeSummary(connections: ConnectionEvent[]): SummaryStats {
  return connections.reduce(
    (summary, connection) => {
      summary.total += 1;
      summary[connection.riskLevel] += 1;
      return summary;
    },
    { safe: 0, unknown: 0, suspicious: 0, total: 0 }
  );
}

export function sortConnections(connections: ConnectionEvent[]) {
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

export function mergeConnections(
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

export function mergeAlerts(current: AlertRecord[], incoming: AlertRecord[]): AlertRecord[] {
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

export function mergeActivity(current: ActivityEvent[], incoming: ActivityEvent[]): ActivityEvent[] {
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

export function normalizeQuery(value: string) {
  return value.trim().toLowerCase();
}

export function connectionSearchTerms(connection: ConnectionEvent) {
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

export function matchesConnectionQuery(connection: ConnectionEvent, query: string) {
  const normalizedQuery = normalizeQuery(query);
  if (!normalizedQuery) {
    return true;
  }
  return connectionSearchTerms(connection).includes(normalizedQuery);
}

export function matchesAlertQuery(alert: AlertRecord, query: string) {
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

export function matchesActivityQuery(event: ActivityEvent, query: string) {
  const normalizedQuery = normalizeQuery(query);
  if (!normalizedQuery) {
    return true;
  }

  return `${event.changeType} ${connectionSearchTerms(event.connection)}`
    .toLowerCase()
    .includes(normalizedQuery);
}

export function filterLabel(value: ConnectionFilter) {
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

export function normalizeState(state: string) {
  return state.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

export function isEstablishedTcp(connection: ConnectionEvent) {
  return (
    connection.protocol.toLowerCase() === "tcp" &&
    normalizeState(connection.state) === "established"
  );
}

export function isPassiveConnection(connection: ConnectionEvent) {
  const normalizedState = normalizeState(connection.state);
  return (
    connection.direction === "listening" ||
    normalizedState === "timewait" ||
    normalizedState === "closewait"
  );
}

export function matchesStateFilter(connection: ConnectionEvent, filter: MonitorStateFilter) {
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

export function matchesDirectionFilter(
  connection: ConnectionEvent,
  filter: MonitorDirectionFilter
) {
  if (filter === "all") {
    return true;
  }

  return connection.direction === filter;
}

export function matchesAlertStateFilter(alert: AlertRecord, filter: MonitorStateFilter) {
  if (filter === "all") {
    return true;
  }

  return alert.connection ? matchesStateFilter(alert.connection, filter) : false;
}

export function matchesAlertDirectionFilter(
  alert: AlertRecord,
  filter: MonitorDirectionFilter
) {
  if (filter === "all") {
    return true;
  }

  return alert.connection ? matchesDirectionFilter(alert.connection, filter) : false;
}

export function endpointLabel(connection: ConnectionEvent, mode: "local" | "remote") {
  if (mode === "local") {
    return `${connection.localAddress}:${connection.localPort}`;
  }

  return connection.remoteAddress && connection.remotePort
    ? `${connection.remoteAddress}:${connection.remotePort}`
    : "";
}

export function alertEndpointLabel(alert: AlertRecord, mode: "local" | "remote") {
  if (!alert.connection) {
    return "";
  }

  return endpointLabel(alert.connection, mode);
}

export function sortConnectionsByMode(
  connections: ConnectionEvent[],
  sortMode: MonitorSort
) {
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
      return (
        right.score - left.score ||
        new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
      );
    }

    return (
      right.confidence - left.confidence ||
      new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    );
  });

  return sorted;
}

export function sortAlertsByMode(alerts: AlertRecord[], sortMode: MonitorSort) {
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
        ) || (left.connection?.pid ?? 0) - (right.connection?.pid ?? 0)
      );
    }

    if (sortMode === "remote") {
      return (
        alertEndpointLabel(left, "remote").localeCompare(
          alertEndpointLabel(right, "remote")
        ) || right.score - left.score
      );
    }

    if (sortMode === "local") {
      return (
        alertEndpointLabel(left, "local").localeCompare(
          alertEndpointLabel(right, "local")
        ) || right.score - left.score
      );
    }

    if (sortMode === "score") {
      return (
        right.score - left.score ||
        new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
      );
    }

    return (
      right.confidence - left.confidence ||
      new Date(right.updatedAt).getTime() - new Date(left.updatedAt).getTime()
    );
  });

  return sorted;
}

export function sortActivityEventsByMode(
  events: ActivityEvent[],
  sortMode: MonitorSort
) {
  const weights = { suspicious: 3, unknown: 2, safe: 1 };
  const sorted = [...events];

  sorted.sort((left, right) => {
    if (sortMode === "risk") {
      return (
        weights[right.connection.riskLevel] - weights[left.connection.riskLevel] ||
        right.connection.score - left.connection.score ||
        new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
      );
    }

    if (sortMode === "recent") {
      return new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime();
    }

    if (sortMode === "process") {
      return (
        left.connection.process.name.localeCompare(right.connection.process.name) ||
        left.connection.pid - right.connection.pid
      );
    }

    if (sortMode === "remote") {
      return (
        endpointLabel(left.connection, "remote").localeCompare(
          endpointLabel(right.connection, "remote")
        ) || right.connection.score - left.connection.score
      );
    }

    if (sortMode === "local") {
      return (
        endpointLabel(left.connection, "local").localeCompare(
          endpointLabel(right.connection, "local")
        ) || right.connection.score - left.connection.score
      );
    }

    if (sortMode === "score") {
      return (
        right.connection.score - left.connection.score ||
        new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
      );
    }

    return (
      right.connection.confidence - left.connection.confidence ||
      new Date(right.timestamp).getTime() - new Date(left.timestamp).getTime()
    );
  });

  return sorted;
}

export function tabMeta(tab: AppTab) {
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

export function buildStrictAllowRule(connection: ConnectionEvent): Partial<AllowRule> {
  return {
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
  };
}

export function buildProcessAllowRule(connection: ConnectionEvent): Partial<AllowRule> {
  return {
    label: `Trusted process ${connection.process.name}`,
    enabled: true,
    processName: connection.process.name,
    signer: connection.process.signer,
    exePath: connection.process.exePath,
    sha256: connection.process.sha256,
    remotePattern: null,
    port: null,
    protocol: null,
    direction: null,
    notes: `Created as a process-wide trust rule on ${new Date().toLocaleString()}`
  };
}
