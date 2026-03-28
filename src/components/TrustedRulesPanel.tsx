import { useMemo, useState } from "react";
import type { AllowRule } from "../types";

interface TrustedRulesPanelProps {
  allowRules: AllowRule[];
  onDelete: (rule: AllowRule) => void;
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
    rule.port?.toString()
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return haystack.includes(normalizedQuery);
}

export function TrustedRulesPanel({ allowRules, onDelete }: TrustedRulesPanelProps) {
  const [openRuleId, setOpenRuleId] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const filteredRules = useMemo(
    () => allowRules.filter((rule) => matchesRuleQuery(rule, query)),
    [allowRules, query]
  );

  function toggleRule(ruleId: string) {
    setOpenRuleId((current) => (current === ruleId ? null : ruleId));
  }

  return (
    <div className="panel rules-panel rules-panel--standalone">
      <div className="rules-panel__header">
        <div className="rules-panel__header-copy">
          <p className="eyebrow">Trusted rules</p>
          <h2>Approved exceptions</h2>
          <p className="panel__muted">Pinned rules for legitimate connections and approved traffic patterns.</p>
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
                      <span className="panel__muted">
                        Created {new Date(rule.createdAt).toLocaleString()}
                      </span>
                      <span className="rule-item__state">
                        {isOpen ? "Hide details" : "Show details"}
                      </span>
                    </div>
                  </div>
                </button>

                {isOpen ? (
                  <div className="rule-item__body">
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

                    <div className="rule-item__actions">
                      <button
                        type="button"
                        className="action-button action-button--danger"
                        onClick={() => onDelete(rule)}
                      >
                        Delete rule
                      </button>
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
