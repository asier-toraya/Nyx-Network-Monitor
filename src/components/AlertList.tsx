import { useMemo, useState } from "react";
import { groupAlertsByOwner } from "../lib/processGrouping";
import type { AlertRecord, RiskLevel } from "../types";

interface AlertListProps {
  alerts: AlertRecord[];
  selectedAlertId: string | null;
  onSelect: (alert: AlertRecord) => void;
  fullHeight?: boolean;
}

const riskWeights: Record<RiskLevel, number> = {
  safe: 1,
  unknown: 2,
  suspicious: 3
};

function getRiskLabel(riskLevel: RiskLevel) {
  if (riskLevel === "safe") {
    return "Secure";
  }

  if (riskLevel === "unknown") {
    return "Unidentified";
  }

  return "Suspicious";
}

function getHighestRiskAlert(alerts: AlertRecord[]) {
  return alerts.reduce((highest, current) => {
    if (!highest) {
      return current;
    }

    const currentWeight = riskWeights[current.riskLevel];
    const highestWeight = riskWeights[highest.riskLevel];

    if (currentWeight !== highestWeight) {
      return currentWeight > highestWeight ? current : highest;
    }

    return new Date(current.updatedAt).getTime() > new Date(highest.updatedAt).getTime()
      ? current
      : highest;
  }, alerts[0]);
}

function formatGroupSummary(alerts: AlertRecord[]) {
  const highestRiskAlert = getHighestRiskAlert(alerts);
  const updatedAt = alerts.reduce((latest, current) => {
    return new Date(current.updatedAt).getTime() > latest ? new Date(current.updatedAt).getTime() : latest;
  }, 0);
  const totalOccurrences = alerts.reduce((total, alert) => total + alert.occurrenceCount, 0);

  return `${alerts.length} alerts | Highest ${getRiskLabel(highestRiskAlert.riskLevel)} | Seen ${totalOccurrences}x | Updated ${new Date(updatedAt).toLocaleString()}`;
}

export function AlertList({
  alerts,
  selectedAlertId,
  onSelect,
  fullHeight = false
}: AlertListProps) {
  const groups = useMemo(() => groupAlertsByOwner(alerts), [alerts]);
  const hasGroupedAlerts = groups.some((group) => group.items.length > 1);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  function toggleGroup(key: string) {
    setExpandedGroups((current) => ({
      ...current,
      [key]: !current[key]
    }));
  }

  function renderAlert(alert: AlertRecord, nested = false) {
    return (
      <button
        key={alert.id}
        type="button"
        className={`alert-item ${selectedAlertId === alert.id ? "is-selected" : ""} ${nested ? "alert-item--nested" : ""}`.trim()}
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
    );
  }

  return (
    <div className={`panel alert-panel ${fullHeight ? "panel--expanded" : ""}`.trim()}>
      <div className="panel__header">
        <div>
          <p className="eyebrow">Alerts</p>
          <h2>Open alerts</h2>
        </div>
        <span className="panel__muted">
          {hasGroupedAlerts ? `${groups.length} groups / ${alerts.length} open` : `${alerts.length} open`}
        </span>
      </div>
      <div className="alert-list">
        {alerts.length === 0 ? (
          <p className="empty-state">No open alerts.</p>
        ) : (
          groups.map((group) => {
            const isExpandable = group.items.length > 1;

            if (!isExpandable) {
              return renderAlert(group.items[0]);
            }

            const hasSelectedAlert = group.items.some((alert) => alert.id === selectedAlertId);
            const isExpanded = (expandedGroups[group.key] ?? false) || hasSelectedAlert;
            const highestRiskAlert = getHighestRiskAlert(group.items);

            return (
              <article
                key={group.key}
                className={`alert-group ${isExpanded ? "is-open" : ""} ${hasSelectedAlert ? "is-selected" : ""}`.trim()}
              >
                <button
                  type="button"
                  className="alert-group__button"
                  onClick={() => toggleGroup(group.key)}
                >
                  <span className={`alert-item__bar alert-item__bar--${highestRiskAlert.riskLevel}`} />
                  <span className="alert-group__summary">
                    <strong>{group.label}</strong>
                    <span>{formatGroupSummary(group.items)}</span>
                  </span>
                  <span className="alert-group__toggle">
                    {isExpanded ? "Hide" : "Show"} {group.items.length}
                  </span>
                </button>

                {isExpanded ? (
                  <div className="alert-group__body">
                    {group.items.map((alert) => renderAlert(alert, true))}
                  </div>
                ) : null}
              </article>
            );
          })
        )}
      </div>
    </div>
  );
}
