import type { CommandExecutionResult } from "../types";

interface CommandOutputModalProps {
  title: string;
  result: CommandExecutionResult | null;
  loading: boolean;
  error: string | null;
  onClose: () => void;
  onRefresh: () => void;
}

export function CommandOutputModal({
  title,
  result,
  loading,
  error,
  onClose,
  onRefresh
}: CommandOutputModalProps) {
  return (
    <div className="detail-modal" role="dialog" aria-modal="true" onClick={onClose}>
      <aside className="panel command-modal" onClick={(event) => event.stopPropagation()}>
        <div className="detail-modal__header">
          <div className="detail-modal__headline">
            <p className="eyebrow">Raw host output</p>
            <h2>{title}</h2>
            <p className="panel__muted">
              {result
                ? `Last updated ${new Date(result.executedAt).toLocaleString()}`
                : "Use this view to compare the app model with the raw operating-system command output."}
            </p>
          </div>

          <div className="detail-modal__header-actions">
            <button type="button" className="action-button" onClick={onRefresh} disabled={loading}>
              {loading ? "Refreshing..." : "Refresh"}
            </button>
            <button type="button" className="action-button action-button--quiet" onClick={onClose}>
              Close
            </button>
          </div>
        </div>

        <div className="detail-modal__body command-modal__body">
          {result ? (
            <section className="detail-section command-modal__section">
              <div className="detail-section__header">
                <div>
                  <p className="eyebrow">Executed command</p>
                  <h3>{result.title}</h3>
                </div>
                <span className={`command-badge ${result.success ? "is-success" : "is-error"}`}>
                  {result.success ? "Completed" : "Returned warnings"}
                </span>
              </div>

              <div className="command-console command-console--modal">
                <div className="command-console__header">
                  <span className="detail-label">Command</span>
                  <code className="mono">{result.command}</code>
                </div>
                <pre className="command-console__output">{result.output}</pre>
              </div>
            </section>
          ) : null}

          {loading ? (
            <section className="detail-section">
              <p className="empty-state">Running command and collecting output...</p>
            </section>
          ) : null}

          {error ? (
            <div className="banner-error">{error}</div>
          ) : null}
        </div>
      </aside>
    </div>
  );
}
