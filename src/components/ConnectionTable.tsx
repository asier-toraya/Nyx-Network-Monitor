import { Fragment, useMemo, useState } from "react";
import { getConnectionIdentitySummary, getConnectionRiskLabel } from "../lib/connectionPresentation";
import { groupConnectionsByOwner } from "../lib/processGrouping";
import type { ConnectionEvent, RiskLevel } from "../types";

interface ConnectionTableProps {
  connections: ConnectionEvent[];
  selectedId: string | null;
  onSelect: (connection: ConnectionEvent) => void;
}

const riskWeights: Record<RiskLevel, number> = {
  safe: 1,
  unknown: 2,
  suspicious: 3
};

function getHighestRiskConnection(connections: ConnectionEvent[]) {
  return connections.reduce((highest, current) => {
    if (!highest) {
      return current;
    }

    const currentWeight = riskWeights[current.riskLevel];
    const highestWeight = riskWeights[highest.riskLevel];

    if (currentWeight !== highestWeight) {
      return currentWeight > highestWeight ? current : highest;
    }

    return new Date(current.timestamp).getTime() > new Date(highest.timestamp).getTime()
      ? current
      : highest;
  }, connections[0]);
}

function countUniqueRemoteEndpoints(connections: ConnectionEvent[]) {
  return new Set(
    connections.map((connection) =>
      connection.remoteAddress && connection.remotePort
        ? `${connection.remoteAddress}:${connection.remotePort}`
        : `listener:${connection.localAddress}:${connection.localPort}`
    )
  ).size;
}

function formatGroupSummary(connections: ConnectionEvent[]) {
  const highestRiskConnection = getHighestRiskConnection(connections);
  const latestTimestamp = connections.reduce((latest, connection) => {
    return new Date(connection.timestamp).getTime() > latest
      ? new Date(connection.timestamp).getTime()
      : latest;
  }, 0);

  return `${connections.length} connections | ${countUniqueRemoteEndpoints(connections)} endpoints | Highest ${getConnectionRiskLabel(highestRiskConnection)} | Updated ${new Date(latestTimestamp).toLocaleString()}`;
}

export function ConnectionTable({
  connections,
  selectedId,
  onSelect
}: ConnectionTableProps) {
  const groups = useMemo(() => groupConnectionsByOwner(connections), [connections]);
  const hasGroupedConnections = groups.some((group) => group.items.length > 1);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  function toggleGroup(key: string) {
    setExpandedGroups((current) => ({
      ...current,
      [key]: !current[key]
    }));
  }

  function renderConnectionRow(connection: ConnectionEvent, nested = false) {
    const normalizedState = connection.state.replace(/[^a-z0-9]/gi, "").toLowerCase();
    const isPassiveRow =
      connection.direction === "listening" ||
      normalizedState === "timewait" ||
      normalizedState === "closewait";

    return (
      <tr
        key={connection.id}
        className={`${selectedId === connection.id ? "is-selected" : ""} ${
          isPassiveRow ? "is-passive" : ""
        } ${nested ? "connection-group__child" : ""}`.trim()}
        onClick={() => onSelect(connection)}
      >
        <td>
          <span className={`risk-pill risk-pill--${connection.riskLevel}`}>
            {getConnectionRiskLabel(connection)}
          </span>
        </td>
        <td>
          <strong>{connection.process.name}</strong>
          <span>PID {connection.pid}</span>
        </td>
        <td className="truncate-cell">
          {connection.process.exePath ?? "Unknown path"}
        </td>
        <td>{`${connection.localAddress}:${connection.localPort}`}</td>
        <td>
          {connection.remoteAddress && connection.remotePort
            ? (
              <>
                <strong>{`${connection.remoteAddress}:${connection.remotePort}`}</strong>
                <span>
                  {connection.destination?.hostname ??
                    connection.destination?.organization ??
                    "No DNS/ASN enrichment"}
                </span>
              </>
            )
            : "Listener / n/a"}
        </td>
        <td>{`${connection.protocol} / ${connection.direction}`}</td>
        <td>{connection.state}</td>
        <td>{getConnectionIdentitySummary(connection)}</td>
      </tr>
    );
  }

  return (
    <div className="panel table-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Live connections</p>
          <h2>Connections</h2>
        </div>
        <span className="panel__muted">
          {hasGroupedConnections
            ? `${groups.length} groups / ${connections.length} rows`
            : `${connections.length} rows`}
        </span>
      </div>
      <div className="table-wrap">
        {connections.length === 0 ? (
          <div className="empty-table-state">
            <strong>No connections match the current filter.</strong>
            <span>Clear the filter or wait for new activity.</span>
          </div>
        ) : (
          <table className="connection-table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Process</th>
                <th>Path</th>
                <th>Local</th>
                <th>Remote</th>
                <th>Protocol</th>
                <th>State</th>
                <th>Signer</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => {
                const isExpandable = group.items.length > 1;

                if (!isExpandable) {
                  return renderConnectionRow(group.items[0]);
                }

                const hasSelectedConnection = group.items.some(
                  (connection) => connection.id === selectedId
                );
                const isExpanded = (expandedGroups[group.key] ?? false) || hasSelectedConnection;
                const highestRiskConnection = getHighestRiskConnection(group.items);

                return (
                  <Fragment key={group.key}>
                    <tr className={`connection-group-row ${hasSelectedConnection ? "is-selected" : ""}`.trim()}>
                      <td colSpan={8}>
                        <button
                          type="button"
                          className="connection-group__button"
                          onClick={() => toggleGroup(group.key)}
                        >
                          <span className={`risk-pill risk-pill--${highestRiskConnection.riskLevel}`}>
                            {getConnectionRiskLabel(highestRiskConnection)}
                          </span>
                          <span className="connection-group__summary">
                            <strong>{group.label}</strong>
                            <span>{formatGroupSummary(group.items)}</span>
                          </span>
                          <span className="connection-group__toggle">
                            {isExpanded ? "Hide" : "Show"} {group.items.length}
                          </span>
                        </button>
                      </td>
                    </tr>

                    {isExpanded ? group.items.map((connection) => renderConnectionRow(connection, true)) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
