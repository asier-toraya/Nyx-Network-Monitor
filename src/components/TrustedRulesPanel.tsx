import { useEffect, useMemo, useState } from "react";
import type { AllowRule } from "../types";

interface TrustedRulesPanelProps {
  allowRules: AllowRule[];
  onDelete: (rule: AllowRule) => void;
  onUpdate: (rule: AllowRule, changes: Partial<AllowRule>) => Promise<void>;
}

interface RuleDraft {
  label: string;
  processName: string;
  remotePattern: string;
  protocol: string;
  direction: string;
  port: string;
  signer: string;
  exePath: string;
  sha256: string;
  notes: string;
}

function formatRulePort(rule: AllowRule) {
  return rule.port ? `Port ${rule.port}` : "Any port";
}

function formatSummary(rule: AllowRule) {
  return [
    rule.processName ?? "Any process",
    rule.remotePattern ?? "Any target",
    rule.protocol ?? "Any protocol",
    rule.direction ?? "Any direction"
  ].join(" | ");
}

function matchesRuleQuery(rule: AllowRule, query: string) {
  const normalizedQuery = query.trim().toLowerCase();

  if (!normalizedQuery) {
    return true;
  }

  const haystack = [
    rule.label,
    rule.processName,
    rule.remotePattern,
    rule.protocol,
    rule.direction,
    rule.signer,
    rule.exePath,
    rule.sha256,
    rule.notes,
    rule.port?.toString(),
    rule.enabled ? "enabled" : "disabled"
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return haystack.includes(normalizedQuery);
}

function toDraft(rule: AllowRule): RuleDraft {
  return {
    label: rule.label,
    processName: rule.processName ?? "",
    remotePattern: rule.remotePattern ?? "",
    protocol: rule.protocol ?? "",
    direction: rule.direction ?? "",
    port: rule.port?.toString() ?? "",
    signer: rule.signer ?? "",
    exePath: rule.exePath ?? "",
    sha256: rule.sha256 ?? "",
    notes: rule.notes ?? ""
  };
}

export function TrustedRulesPanel({
  allowRules,
  onDelete,
  onUpdate
}: TrustedRulesPanelProps) {
  const [openRuleId, setOpenRuleId] = useState<string | null>(null);
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const [query, setQuery] = useState("");
  const [savingRuleId, setSavingRuleId] = useState<string | null>(null);

  const filteredRules = useMemo(
    () => allowRules.filter((rule) => matchesRuleQuery(rule, query)),
    [allowRules, query]
  );

  useEffect(() => {
    if (!editingRuleId) {
      return;
    }

    const currentRule = allowRules.find((rule) => rule.id === editingRuleId);
    if (!currentRule) {
      setEditingRuleId(null);
      setDraft(null);
    }
  }, [allowRules, editingRuleId]);

  function toggleRule(ruleId: string) {
    setOpenRuleId((current) => (current === ruleId ? null : ruleId));
  }

  function handleStartEdit(rule: AllowRule) {
    setOpenRuleId(rule.id);
    setEditingRuleId(rule.id);
    setDraft(toDraft(rule));
  }

  function handleCancelEdit() {
    setEditingRuleId(null);
    setDraft(null);
  }

  async function handleSave(rule: AllowRule) {
    if (!draft) {
      return;
    }

    setSavingRuleId(rule.id);
    try {
      await onUpdate(rule, {
        label: draft.label.trim() || rule.label,
        processName: draft.processName,
        remotePattern: draft.remotePattern,
        protocol: draft.protocol,
        direction: draft.direction,
        port: draft.port.trim() ? Number(draft.port) : null,
        signer: draft.signer,
        exePath: draft.exePath,
        sha256: draft.sha256,
        notes: draft.notes
      });
      setEditingRuleId(null);
      setDraft(null);
    } finally {
      setSavingRuleId(null);
    }
  }

  async function handleToggleEnabled(rule: AllowRule) {
    setSavingRuleId(rule.id);
    try {
      await onUpdate(rule, { enabled: !rule.enabled });
    } finally {
      setSavingRuleId(null);
    }
  }

  return (
    <div className="panel rules-panel rules-panel--standalone">
      <div className="rules-panel__header">
        <div className="rules-panel__header-copy">
          <p className="eyebrow">Trusted rules</p>
          <h2>Approved exceptions</h2>
          <p className="panel__muted">
            Pinned rules for legitimate connections and approved traffic patterns.
          </p>
        </div>
        <div className="rules-panel__tools">
          <span className="panel__muted">
            {filteredRules.length} of {allowRules.length} rules
          </span>
          <label className="rules-search">
            <span className="sr-only">Search trusted rules</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search rules"
            />
          </label>
        </div>
      </div>

      {allowRules.length === 0 ? (
        <div className="empty-table-state">
          <strong>No trusted rules configured.</strong>
          <span>Rules will appear here when you mark a connection as trusted.</span>
        </div>
      ) : filteredRules.length === 0 ? (
        <div className="empty-table-state">
          <strong>No matching trusted rules.</strong>
          <span>Try another process name, target, protocol, direction, path or hash.</span>
        </div>
      ) : (
        <div className="rule-list rule-list--standalone">
          {filteredRules.map((rule) => {
            const isOpen = openRuleId === rule.id;
            const isEditing = editingRuleId === rule.id && draft !== null;
            const isSaving = savingRuleId === rule.id;

            return (
              <article
                key={rule.id}
                className={`rule-item rule-item--accordion ${isOpen ? "is-open" : ""}`}
              >
                <button
                  type="button"
                  className="rule-item__toggle"
                  onClick={() => toggleRule(rule.id)}
                  aria-expanded={isOpen}
                >
                  <div className="rule-item__header">
                    <div className="rule-item__title">
                      <strong>{rule.label}</strong>
                      <span>{formatSummary(rule)}</span>
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
                    {isEditing ? (
                      <div className="rule-edit-grid">
                        <label>
                          Label
                          <input
                            type="text"
                            value={draft.label}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, label: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Process
                          <input
                            type="text"
                            value={draft.processName}
                            onChange={(event) =>
                              setDraft((current) =>
                                current
                                  ? { ...current, processName: event.target.value }
                                  : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Target
                          <input
                            type="text"
                            value={draft.remotePattern}
                            onChange={(event) =>
                              setDraft((current) =>
                                current
                                  ? { ...current, remotePattern: event.target.value }
                                  : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Port
                          <input
                            type="number"
                            min={1}
                            max={65535}
                            value={draft.port}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, port: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Protocol
                          <input
                            type="text"
                            value={draft.protocol}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, protocol: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Direction
                          <input
                            type="text"
                            value={draft.direction}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, direction: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label>
                          Signer
                          <input
                            type="text"
                            value={draft.signer}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, signer: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label className="rule-edit-grid__wide">
                          Executable path
                          <input
                            type="text"
                            value={draft.exePath}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, exePath: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label className="rule-edit-grid__wide">
                          Hash
                          <input
                            type="text"
                            value={draft.sha256}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, sha256: event.target.value } : current
                              )
                            }
                          />
                        </label>
                        <label className="rule-edit-grid__wide">
                          Notes
                          <textarea
                            rows={3}
                            value={draft.notes}
                            onChange={(event) =>
                              setDraft((current) =>
                                current ? { ...current, notes: event.target.value } : current
                              )
                            }
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
                            onClick={() => void handleSave(rule)}
                            disabled={isSaving}
                          >
                            {isSaving ? "Saving..." : "Save changes"}
                          </button>
                          <button
                            type="button"
                            className="action-button"
                            onClick={handleCancelEdit}
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
                            onClick={() => handleStartEdit(rule)}
                            disabled={isSaving}
                          >
                            Edit rule
                          </button>
                          <button
                            type="button"
                            className="action-button"
                            onClick={() => void handleToggleEnabled(rule)}
                            disabled={isSaving}
                          >
                            {rule.enabled ? "Disable rule" : "Enable rule"}
                          </button>
                          <button
                            type="button"
                            className="action-button action-button--danger"
                            onClick={() => onDelete(rule)}
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
          })}
        </div>
      )}
    </div>
  );
}
