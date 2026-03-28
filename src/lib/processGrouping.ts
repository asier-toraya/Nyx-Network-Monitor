import type { AlertRecord, ConnectionEvent, ProcessIdentity } from "../types";

export interface ProcessGroup<T> {
  key: string;
  label: string;
  pid: number | null;
  pidLabel: string;
  processName: string;
  items: T[];
}

interface ProcessOwner {
  exePath: string | null;
  pid: number | null;
  processName: string;
}

function normalizeProcessName(value: string | null | undefined) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : "Unknown process";
}

function toProcessOwner(process: ProcessIdentity | null | undefined, pid: number | null | undefined): ProcessOwner {
  const normalizedPid = pid && pid > 0 ? pid : null;

  return {
    processName: normalizeProcessName(process?.name),
    pid: normalizedPid,
    exePath: process?.exePath ?? null
  };
}

function buildGroupKey(owner: ProcessOwner) {
  if (owner.pid !== null) {
    return `pid:${owner.pid}`;
  }

  if (owner.exePath) {
    return `path:${owner.exePath.toLowerCase()}`;
  }

  return `name:${owner.processName.toLowerCase()}`;
}

function buildGroupLabel(owner: ProcessOwner) {
  return owner.pid !== null
    ? `${owner.processName} (PID ${owner.pid})`
    : owner.processName;
}

function buildPidLabel(owner: ProcessOwner) {
  return owner.pid !== null ? `PID ${owner.pid}` : "No active PID";
}

function groupByOwner<T>(
  items: T[],
  getOwner: (item: T) => ProcessOwner
): ProcessGroup<T>[] {
  const groups = new Map<string, ProcessGroup<T>>();

  items.forEach((item) => {
    const owner = getOwner(item);
    const key = buildGroupKey(owner);
    const existing = groups.get(key);

    if (existing) {
      existing.items.push(item);
      return;
    }

    groups.set(key, {
      key,
      label: buildGroupLabel(owner),
      pid: owner.pid,
      pidLabel: buildPidLabel(owner),
      processName: owner.processName,
      items: [item]
    });
  });

  return Array.from(groups.values());
}

export function groupConnectionsByOwner(connections: ConnectionEvent[]) {
  return groupByOwner(connections, (connection) =>
    toProcessOwner(connection.process, connection.pid)
  );
}

export function groupAlertsByOwner(alerts: AlertRecord[]) {
  return groupByOwner(alerts, (alert) => {
    if (!alert.connection) {
      return toProcessOwner(null, null);
    }

    return toProcessOwner(alert.connection.process, alert.connection.pid);
  });
}
