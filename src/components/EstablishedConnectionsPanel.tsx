import { getConnectionRiskLabel } from "../lib/connectionPresentation";
import type { ConnectionEvent } from "../types";

interface EstablishedConnectionsPanelProps {
  connections: ConnectionEvent[];
  selectedId: string | null;
  onSelect: (connection: ConnectionEvent) => void;
  onOpenModal: () => void;
}

export function EstablishedConnectionsPanel({
  connections,
  selectedId,
  onSelect,
  onOpenModal
}: EstablishedConnectionsPanelProps) {
  return (
    <div className="panel table-panel established-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Established connections</p>
          <h2>Active TCP sessions</h2>
        </div>
        <div className="panel__header-actions">
          <span className="panel__muted">{connections.length} rows</span>
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
              {connections.map((connection) => (
                <tr
                  key={connection.id}
                  className={selectedId === connection.id ? "is-selected" : ""}
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
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
