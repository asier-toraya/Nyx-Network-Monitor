import { useEffect, useMemo, useState } from "react";
import { matchesRuleQuery, toRuleDraft, type RuleDraft } from "../lib/trustedRules";
import type { AllowRule } from "../types";
import { TrustedRuleItem } from "./TrustedRuleItem";

interface TrustedRulesPanelProps {
  allowRules: AllowRule[];
  onDelete: (rule: AllowRule) => void;
  onUpdate: (rule: AllowRule, changes: Partial<AllowRule>) => Promise<void>;
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
    setDraft(toRuleDraft(rule));
  }

  function handleCancelEdit() {
    setEditingRuleId(null);
    setDraft(null);
  }

  function handleDraftChange(changes: Partial<RuleDraft>) {
    setDraft((current) => (current ? { ...current, ...changes } : current));
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
          {filteredRules.map((rule) => (
            <TrustedRuleItem
              key={rule.id}
              rule={rule}
              isOpen={openRuleId === rule.id}
              isEditing={editingRuleId === rule.id && draft !== null}
              isSaving={savingRuleId === rule.id}
              draft={editingRuleId === rule.id ? draft : null}
              onToggle={() => toggleRule(rule.id)}
              onStartEdit={() => handleStartEdit(rule)}
              onCancelEdit={handleCancelEdit}
              onSave={() => void handleSave(rule)}
              onToggleEnabled={() => void handleToggleEnabled(rule)}
              onDelete={() => onDelete(rule)}
              onDraftChange={handleDraftChange}
            />
          ))}
        </div>
      )}
    </div>
  );
}
