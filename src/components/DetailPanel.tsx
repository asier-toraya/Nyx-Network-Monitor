import { useEffect, useMemo, useState } from "react";
import {
  formatUserContext,
  getConnectionExplanation,
  getConnectionIdentityStatus,
  getConnectionRiskLabel
} from "../lib/connectionPresentation";
import { executeConnectionCommand } from "../lib/tauri";
import type {
  AlertRecord,
  CommandExecutionResult,
  ConnectionCommandAction,
  ConnectionEvent
} from "../types";

interface DetailPanelProps {
  connection: ConnectionEvent | null;
  alert: AlertRecord | null;
  onAllow: (connection: ConnectionEvent) => void;
  onDismiss: (alert: AlertRecord) => void;
  onCopyCommand: (value: string) => void;
  onClose: () => void;
}

interface DetailAction {
  id: ConnectionCommandAction;
  label: string;
}

export function DetailPanel({
  connection,
  alert,
  onAllow,
  onDismiss,
  onCopyCommand,
  onClose
}: DetailPanelProps) {
  const [commandResult, setCommandResult] = useState<CommandExecutionResult | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);
  const [runningAction, setRunningAction] = useState<ConnectionCommandAction | null>(null);

  useEffect(() => {
    setCommandResult(null);
    setCommandError(null);
    setRunningAction(null);
  }, [connection?.id]);

  const isSvchost = connection?.process.name.toLowerCase() === "svchost.exe";
  const hasLiveProcessOwner =
    connection != null &&
    connection.pid > 0 &&
    connection.process.name.toLowerCase() !== "unknown";

  const actions = useMemo<DetailAction[]>(() => {
    const items: DetailAction[] = [
      { id: "view_process", label: "View Process" },
      { id: "get_executable_path", label: "Get Executable Path" }
    ];

    if (isSvchost && hasLiveProcessOwner) {
      items.push(
        { id: "check_svchost_services", label: "Check svchost Services" },
        { id: "get_svchost_service_details", label: "Get Service Details" }
      );
    }

    return items;
  }, [hasLiveProcessOwner, isSvchost]);

  if (!connection) {
    return null;
  }

  const activeConnection = connection;

  const remoteEndpoint =
    activeConnection.remoteAddress && activeConnection.remotePort
      ? `${activeConnection.remoteAddress}:${activeConnection.remotePort}`
      : "Listener / n/a";

  const identityStatus = getConnectionIdentityStatus(activeConnection);

  const explanation = getConnectionExplanation(activeConnection);

  async function handleRunAction(action: ConnectionCommandAction) {
    setRunningAction(action);
    setCommandError(null);

    try {
      const result = await executeConnectionCommand({
        action,
        pid: activeConnection.pid,
        processName: activeConnection.process.name,
        localAddress: activeConnection.localAddress,
        localPort: activeConnection.localPort,
        remoteAddress: activeConnection.remoteAddress,
        remotePort: activeConnection.remotePort
      });

      setCommandResult(result);
    } catch (cause) {
      setCommandError(
        cause instanceof Error ? cause.message : "Failed to execute the requested command"
      );
    } finally {
      setRunningAction(null);
    }
  }

  return (
    <div
      className="detail-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="connection-detail-title"
      onClick={onClose}
    >
      <aside
        className="panel detail-panel detail-panel--modal"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="detail-modal__header">
          <div className="detail-modal__headline">
            <p className="eyebrow">Connection inspection</p>
            <h2 id="connection-detail-title">{activeConnection.process.name}</h2>
            <p className="panel__muted">
              PID {activeConnection.pid} | Captured {new Date(activeConnection.timestamp).toLocaleString()}
            </p>
          </div>

          <div className="detail-modal__header-actions">
            <span className={`risk-pill risk-pill--${activeConnection.riskLevel}`}>
              {getConnectionRiskLabel(activeConnection)}
            </span>
            <button
              type="button"
              className="action-button action-button--quiet"
              onClick={onClose}
            >
              Close
            </button>
          </div>
        </div>

        <div className="detail-modal__body">
          <section className="detail-section">
            <div className="detail-section__header">
              <div>
                <p className="eyebrow">Identity</p>
                <h3>Process profile</h3>
              </div>
              <span className="panel__muted">
                PID {activeConnection.pid} | {activeConnection.process.name}
              </span>
            </div>

            <div className="detail-overview-grid detail-overview-grid--embedded">
              <div className="detail-stat">
                <span className="detail-label">Risk score</span>
                <strong>{activeConnection.score}</strong>
              </div>
              <div className="detail-stat">
                <span className="detail-label">Confidence</span>
                <strong>{activeConnection.confidence}%</strong>
              </div>
              <div className="detail-stat">
                <span className="detail-label">Baseline hits</span>
                <strong>{activeConnection.baselineHits}</strong>
              </div>
              <div className="detail-stat">
                <span className="detail-label">State</span>
                <strong>{activeConnection.state}</strong>
              </div>
            </div>

            <div className="detail-section-grid detail-section-grid--identity">
              <div className="detail-item">
                <span className="detail-label">Executable path</span>
                <p>{activeConnection.process.exePath ?? "Path not available"}</p>
              </div>
              <div className="detail-item">
                <span className="detail-label">Trust status</span>
                <p>{identityStatus}</p>
              </div>
              <div className="detail-item">
                <span className="detail-label">Parent process</span>
                <p>
                  {activeConnection.process.parentName
                    ? `${activeConnection.process.parentName}${
                        activeConnection.process.parentPid
                          ? ` (PID ${activeConnection.process.parentPid})`
                          : ""
                      }`
                    : "Parent context unavailable"}
                </p>
              </div>
              <div className="detail-item">
                <span className="detail-label">User</span>
                <p>{formatUserContext(activeConnection.process.user)}</p>
              </div>
              <div className="detail-item">
                <span className="detail-label">Hash</span>
                <p className="mono">{activeConnection.process.sha256 ?? "Pending or not available"}</p>
              </div>
              <div className="detail-item">
                <span className="detail-label">Hosted services</span>
                <p>
                  {activeConnection.process.hostedServices.length > 0
                    ? activeConnection.process.hostedServices.join(", ")
                    : activeConnection.process.serviceContextPending
                      ? "Resolving hosted services"
                      : "No hosted service data"}
                </p>
              </div>
            </div>
          </section>

          <section className="detail-section">
            <div className="detail-section__header">
              <div>
                <p className="eyebrow">Interactive actions</p>
                <h3>Live host commands</h3>
              </div>
              <span className="panel__muted">
                PID {activeConnection.pid} | {activeConnection.localAddress}:{activeConnection.localPort}
              </span>
            </div>

            <div className="command-action-row">
              {actions.map((action) => (
                <button
                  key={action.id}
                  type="button"
                  className="action-button"
                  onClick={() => void handleRunAction(action.id)}
                  disabled={runningAction !== null || !hasLiveProcessOwner}
                >
                  {runningAction === action.id ? "Running..." : action.label}
                </button>
              ))}
              <button
                type="button"
                className="action-button action-button--primary"
                onClick={() => onAllow(activeConnection)}
              >
                Mark as trusted
              </button>
              {alert ? (
                <button type="button" className="action-button" onClick={() => onDismiss(alert)}>
                  Dismiss alert
                </button>
              ) : null}
              {activeConnection.suggestedFirewallRule ? (
                <button
                  type="button"
                  className="action-button action-button--danger"
                  onClick={() => onCopyCommand(activeConnection.suggestedFirewallRule!)}
                >
                  Copy firewall suggestion
                </button>
              ) : null}
            </div>

            {!hasLiveProcessOwner ? (
              <p className="empty-state">
                No live owning process is available for this entry, so host commands are disabled.
              </p>
            ) : null}

            {commandResult ? (
              <div className="command-console">
                <div className="command-console__header">
                  <div>
                    <span className="detail-label">Last command</span>
                    <strong>{commandResult.title}</strong>
                  </div>
                  <span className={`command-badge ${commandResult.success ? "is-success" : "is-error"}`}>
                    {commandResult.success ? "Completed" : "Returned warnings"}
                  </span>
                </div>
                <code className="mono command-console__command">{commandResult.command}</code>
                <pre className="command-console__output">{commandResult.output}</pre>
              </div>
            ) : (
              <p className="empty-state">
                Run one of the actions above to inspect the process directly from the host.
              </p>
            )}

            {commandError ? <div className="banner-error">{commandError}</div> : null}
          </section>

          {explanation ? (
            <section className="detail-section detail-section--notice">
              <div className="detail-section__header">
                <div>
                  <p className="eyebrow">Listener context</p>
                  <h3>Expected Windows behavior</h3>
                </div>
              </div>
              <div className="detail-item">
                <p>{explanation}</p>
              </div>
            </section>
          ) : null}

          <section className="detail-section detail-section--transport">
            <div className="detail-section__header">
              <div>
                <p className="eyebrow">Transport</p>
                <h3>Network path</h3>
              </div>
              <span className="panel__muted">
                {`${activeConnection.protocol.toUpperCase()} / ${activeConnection.direction}`}
              </span>
            </div>

            <div className="detail-transport-row">
              <div className="detail-item detail-item--inline">
                <span className="detail-label">Local endpoint</span>
                <strong>{`${activeConnection.localAddress}:${activeConnection.localPort}`}</strong>
              </div>
              <div className="detail-item detail-item--inline">
                <span className="detail-label">Remote endpoint</span>
                <strong>{remoteEndpoint}</strong>
              </div>
              <div className="detail-item detail-item--inline">
                <span className="detail-label">Direction</span>
                <strong>{activeConnection.direction}</strong>
              </div>
              <div className="detail-item detail-item--inline">
                <span className="detail-label">Protocol</span>
                <strong>{activeConnection.protocol}</strong>
              </div>
            </div>
          </section>

          <section className="detail-section">
            <div className="detail-section__header">
              <div>
                <p className="eyebrow">Assessment</p>
                <h3>Risk factors</h3>
              </div>
            </div>

            <ul className="reason-list">
              {activeConnection.reasons.map((reason) => (
                <li key={reason.code}>
                  <span className="reason-code">{reason.code}</span>
                  <span>{reason.message}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </aside>
    </div>
  );
}
