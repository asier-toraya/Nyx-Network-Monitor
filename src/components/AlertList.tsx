import type { AlertRecord } from "../types";

interface AlertListProps {
  alerts: AlertRecord[];
  selectedAlertId: string | null;
  onSelect: (alert: AlertRecord) => void;
}

export function AlertList({ alerts, selectedAlertId, onSelect }: AlertListProps) {
  return (
    <div className="panel alert-panel">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Alerts</p>
          <h2>Open alerts</h2>
        </div>
        <span className="panel__muted">{alerts.length} open</span>
      </div>
      <div className="alert-list">
        {alerts.length === 0 ? (
          <p className="empty-state">No open alerts.</p>
        ) : (
          alerts.map((alert) => (
            <button
              key={alert.id}
              type="button"
              className={`alert-item ${selectedAlertId === alert.id ? "is-selected" : ""}`}
              onClick={() => onSelect(alert)}
            >
              <span className={`alert-item__bar alert-item__bar--${alert.riskLevel}`} />
              <span className="alert-item__body">
                <strong>{alert.connection?.process.name ?? "Unknown process"}</strong>
                <span>{alert.recommendedAction}</span>
                <span className="alert-item__meta">
                  Score {alert.score} | Confidence {alert.confidence}% | Seen {alert.occurrenceCount}x
                </span>
                <span className="alert-item__meta">
                  Updated {new Date(alert.updatedAt).toLocaleString()}
                </span>
              </span>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
