import { getConnectionIdentitySummary, getConnectionRiskLabel } from "../lib/connectionPresentation";
import type { ConnectionEvent } from "../types";

interface ConnectionTableProps {
  connections: ConnectionEvent[];
  selectedId: string | null;
  onSelect: (connection: ConnectionEvent) => void;
}

export function ConnectionTable({
  connections,
  selectedId,
  onSelect
}: ConnectionTableProps) {
  return (
    <div className="panel table-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Live connections</p>
          <h2>Connections</h2>
        </div>
        <span className="panel__muted">{connections.length} rows</span>
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
              {connections.map((connection) => {
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
                    }`.trim()}
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
                        ? `${connection.remoteAddress}:${connection.remotePort}`
                        : "Listener / n/a"}
                    </td>
                    <td>{`${connection.protocol} / ${connection.direction}`}</td>
                    <td>{connection.state}</td>
                    <td>{getConnectionIdentitySummary(connection)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
