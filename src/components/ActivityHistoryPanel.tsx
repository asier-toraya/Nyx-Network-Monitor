import { getConnectionRiskLabel } from "../lib/connectionPresentation";
import type { ActivityEvent } from "../types";

interface ActivityHistoryPanelProps {
  events: ActivityEvent[];
  selectedId: string | null;
  onSelect: (event: ActivityEvent) => void;
}

function formatChangeLabel(changeType: string) {
  if (changeType === "opened") {
    return "Opened";
  }
  if (changeType === "closed") {
    return "Closed";
  }
  return "Updated";
}

export function ActivityHistoryPanel({
  events,
  selectedId,
  onSelect
}: ActivityHistoryPanelProps) {
  return (
    <div className="panel table-panel history-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">History</p>
          <h2>Recent activity</h2>
        </div>
        <span className="panel__muted">{events.length} events</span>
      </div>

      <div className="table-wrap">
        {events.length === 0 ? (
          <div className="empty-table-state">
            <strong>No recent connection activity.</strong>
            <span>Changed and closed sockets will appear here as the collector runs.</span>
          </div>
        ) : (
          <table className="connection-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Change</th>
                <th>Risk</th>
                <th>Process</th>
                <th>Local</th>
                <th>Remote</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr
                  key={event.id}
                  className={selectedId === event.id ? "is-selected" : ""}
                  onClick={() => onSelect(event)}
                >
                  <td>{new Date(event.timestamp).toLocaleString()}</td>
                  <td>
                    <span className={`activity-pill activity-pill--${event.changeType}`}>
                      {formatChangeLabel(event.changeType)}
                    </span>
                  </td>
                  <td>
                    <span className={`risk-pill risk-pill--${event.connection.riskLevel}`}>
                      {getConnectionRiskLabel(event.connection)}
                    </span>
                  </td>
                  <td>
                    <strong>{event.connection.process.name}</strong>
                    <span>PID {event.connection.pid}</span>
                  </td>
                  <td>{`${event.connection.localAddress}:${event.connection.localPort}`}</td>
                  <td>
                    {event.connection.remoteAddress && event.connection.remotePort
                      ? `${event.connection.remoteAddress}:${event.connection.remotePort}`
                      : "Listener / n/a"}
                  </td>
                  <td>{event.connection.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
