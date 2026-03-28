import { Fragment, useMemo, useState } from "react";
import { getConnectionRiskLabel } from "../lib/connectionPresentation";
import { groupConnectionsByOwner } from "../lib/processGrouping";
import type { RiskLevel } from "../types";
import type { ConnectionEvent } from "../types";

interface EstablishedConnectionsPanelProps {
  connections: ConnectionEvent[];
  selectedId: string | null;
  onSelect: (connection: ConnectionEvent) => void;
  onOpenModal: () => void;
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

  return `${connections.length} sessions | ${countUniqueRemoteEndpoints(connections)} endpoints | Highest ${getConnectionRiskLabel(highestRiskConnection)} | Updated ${new Date(latestTimestamp).toLocaleString()}`;
}

export function EstablishedConnectionsPanel({
  connections,
  selectedId,
  onSelect,
  onOpenModal
}: EstablishedConnectionsPanelProps) {
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
    return (
      <tr
        key={connection.id}
        className={`${selectedId === connection.id ? "is-selected" : ""} ${nested ? "connection-group__child" : ""}`.trim()}
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
        <td>{`${connection.localAddress}:${connection.localPort}`}</td>
        <td>
          {connection.remoteAddress && connection.remotePort
            ? `${connection.remoteAddress}:${connection.remotePort}`
            : "n/a"}
        </td>
        <td>{connection.state}</td>
        <td>{connection.direction}</td>
      </tr>
    );
  }

  return (
    <div className="panel table-panel established-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Established connections</p>
          <h2>Active TCP sessions</h2>
        </div>
        <div className="panel__header-actions">
          <span className="panel__muted">
            {hasGroupedConnections
              ? `${groups.length} groups / ${connections.length} rows`
              : `${connections.length} rows`}
          </span>
          <button type="button" className="action-button action-button--quiet" onClick={onOpenModal}>
            Raw OS view
          </button>
        </div>
      </div>

      <div className="table-wrap">
        {connections.length === 0 ? (
          <div className="empty-table-state">
            <strong>No established TCP sessions right now.</strong>
            <span>Active sessions will appear here as soon as they are detected.</span>
          </div>
        ) : (
          <table className="connection-table">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Process</th>
                <th>Local</th>
                <th>Remote</th>
                <th>State</th>
                <th>Direction</th>
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
                      <td colSpan={6}>
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
