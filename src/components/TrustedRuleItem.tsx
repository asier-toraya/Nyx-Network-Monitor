import {
  formatRulePort,
  formatRuleSummary,
  type RuleDraft
} from "../lib/trustedRules";
import type { AllowRule } from "../types";

interface TrustedRuleItemProps {
  rule: AllowRule;
  isAlternatingTone: boolean;
  isOpen: boolean;
  isEditing: boolean;
  isSaving: boolean;
  draft: RuleDraft | null;
  onToggle: () => void;
  onStartEdit: () => void;
  onCancelEdit: () => void;
  onSave: () => void;
  onToggleEnabled: () => void;
  onDelete: () => void;
  onDraftChange: (changes: Partial<RuleDraft>) => void;
}

export function TrustedRuleItem({
  rule,
  isAlternatingTone,
  isOpen,
  isEditing,
  isSaving,
  draft,
  onToggle,
  onStartEdit,
  onCancelEdit,
  onSave,
  onToggleEnabled,
  onDelete,
  onDraftChange
}: TrustedRuleItemProps) {
  return (
    <article
      className={`rule-item rule-item--accordion ${isAlternatingTone ? "rule-item--alternate" : ""} ${isOpen ? "is-open" : ""}`.trim()}
    >
      <button
        type="button"
        className="rule-item__toggle"
        onClick={onToggle}
        aria-expanded={isOpen}
      >
        <div className="rule-item__header">
          <div className="rule-item__title">
            <strong>{rule.label}</strong>
            <span>{formatRuleSummary(rule)}</span>
          </div>
          <div className="rule-item__meta">
            <span
              className={`rule-state-pill ${
                rule.enabled ? "rule-state-pill--enabled" : "rule-state-pill--disabled"
              }`}
            >
              {rule.enabled ? "Enabled" : "Disabled"}
            </span>
            <span className="panel__muted">
              Updated {new Date(rule.updatedAt).toLocaleString()}
            </span>
            <span className="rule-item__state">
              {isOpen ? "Hide details" : "Show details"}
            </span>
          </div>
        </div>
      </button>

      {isOpen ? (
        <div className="rule-item__body">
          {isEditing && draft ? (
            <div className="rule-edit-grid">
              <label>
                Label
                <input
                  type="text"
                  value={draft.label}
                  onChange={(event) => onDraftChange({ label: event.target.value })}
                />
              </label>
              <label>
                Process
                <input
                  type="text"
                  value={draft.processName}
                  onChange={(event) => onDraftChange({ processName: event.target.value })}
                />
              </label>
              <label>
                Target
                <input
                  type="text"
                  value={draft.remotePattern}
                  onChange={(event) => onDraftChange({ remotePattern: event.target.value })}
                />
              </label>
              <label>
                Port
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={draft.port}
                  onChange={(event) => onDraftChange({ port: event.target.value })}
                />
              </label>
              <label>
                Protocol
                <input
                  type="text"
                  value={draft.protocol}
                  onChange={(event) => onDraftChange({ protocol: event.target.value })}
                />
              </label>
              <label>
                Direction
                <input
                  type="text"
                  value={draft.direction}
                  onChange={(event) => onDraftChange({ direction: event.target.value })}
                />
              </label>
              <label>
                Signer
                <input
                  type="text"
                  value={draft.signer}
                  onChange={(event) => onDraftChange({ signer: event.target.value })}
                />
              </label>
              <label className="rule-edit-grid__wide">
                Executable path
                <input
                  type="text"
                  value={draft.exePath}
                  onChange={(event) => onDraftChange({ exePath: event.target.value })}
                />
              </label>
              <label className="rule-edit-grid__wide">
                Hash
                <input
                  type="text"
                  value={draft.sha256}
                  onChange={(event) => onDraftChange({ sha256: event.target.value })}
                />
              </label>
              <label className="rule-edit-grid__wide">
                Notes
                <textarea
                  rows={3}
                  value={draft.notes}
                  onChange={(event) => onDraftChange({ notes: event.target.value })}
                />
              </label>
            </div>
          ) : (
            <>
              <div className="rule-facts">
                <div>
                  <span className="detail-label">Process</span>
                  <strong>{rule.processName ?? "Any process"}</strong>
                </div>
                <div>
                  <span className="detail-label">Target</span>
                  <strong>{rule.remotePattern ?? "Any target"}</strong>
                </div>
                <div>
                  <span className="detail-label">Protocol</span>
                  <strong>{rule.protocol ?? "Any protocol"}</strong>
                </div>
                <div>
                  <span className="detail-label">Direction</span>
                  <strong>{rule.direction ?? "Any direction"}</strong>
                </div>
                <div>
                  <span className="detail-label">Port</span>
                  <strong>{formatRulePort(rule)}</strong>
                </div>
                <div>
                  <span className="detail-label">Signer</span>
                  <strong>{rule.signer ?? "Signer not pinned"}</strong>
                </div>
              </div>

              <div className="rule-facts rule-facts--technical">
                <div>
                  <span className="detail-label">Executable path</span>
                  <span>{rule.exePath ?? "Path not pinned"}</span>
                </div>
                <div>
                  <span className="detail-label">Hash</span>
                  <span className="mono">{rule.sha256 ?? "Hash not pinned"}</span>
                </div>
              </div>

              <div className="rule-facts rule-facts--technical">
                <div>
                  <span className="detail-label">Notes</span>
                  <span>{rule.notes ?? "No analyst notes"}</span>
                </div>
                <div>
                  <span className="detail-label">Created</span>
                  <span>{new Date(rule.createdAt).toLocaleString()}</span>
                </div>
              </div>
            </>
          )}

          <div className="rule-item__actions">
            {isEditing ? (
              <>
                <button
                  type="button"
                  className="action-button action-button--primary"
                  onClick={onSave}
                  disabled={isSaving}
                >
                  {isSaving ? "Saving..." : "Save changes"}
                </button>
                <button
                  type="button"
                  className="action-button"
                  onClick={onCancelEdit}
                  disabled={isSaving}
                >
                  Cancel
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  className="action-button"
                  onClick={onStartEdit}
                  disabled={isSaving}
                >
                  Edit rule
                </button>
                <button
                  type="button"
                  className="action-button"
                  onClick={onToggleEnabled}
                  disabled={isSaving}
                >
                  {rule.enabled ? "Disable rule" : "Enable rule"}
                </button>
                <button
                  type="button"
                  className="action-button action-button--danger"
                  onClick={onDelete}
                  disabled={isSaving}
                >
                  Delete rule
                </button>
              </>
            )}
          </div>
        </div>
      ) : null}
    </article>
  );
}
