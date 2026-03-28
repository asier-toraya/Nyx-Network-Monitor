import { useEffect, useMemo, useState } from "react";
import type { AppSettings } from "../types";

interface SettingsPanelProps {
  settings: AppSettings | null;
  onSave: (settings: AppSettings) => Promise<void>;
}

function formatPortsInput(ports: number[]) {
  return ports.join(", ");
}

function parsePortsInput(value: string) {
  const tokens = value
    .split(",")
    .map((token) => token.trim())
    .filter(Boolean);

  const ports: number[] = [];
  const invalidTokens: string[] = [];

  tokens.forEach((token) => {
    if (!/^\d+$/.test(token)) {
      invalidTokens.push(token);
      return;
    }

    const port = Number(token);
    if (port < 1 || port > 65535) {
      invalidTokens.push(token);
      return;
    }

    if (!ports.includes(port)) {
      ports.push(port);
    }
  });

  return { ports, invalidTokens };
}

function normalizeApiKey(value: string | null) {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function samePorts(left: number[], right: number[]) {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((port, index) => port === right[index]);
}

function sameSettings(left: AppSettings, right: AppSettings) {
  return (
    left.pollingIntervalSecs === right.pollingIntervalSecs &&
    left.retentionDays === right.retentionDays &&
    left.baselineLearningThreshold === right.baselineLearningThreshold &&
    left.alertCooldownMinutes === right.alertCooldownMinutes &&
    left.enableDestinationEnrichment === right.enableDestinationEnrichment &&
    left.destinationProvider === right.destinationProvider &&
    left.destinationTtlMinutes === right.destinationTtlMinutes &&
    left.enableReputation === right.enableReputation &&
    left.reputationProvider === right.reputationProvider &&
    normalizeApiKey(left.reputationApiKey) === normalizeApiKey(right.reputationApiKey) &&
    left.reputationTtlMinutes === right.reputationTtlMinutes &&
    samePorts(left.suspiciousPorts, right.suspiciousPorts)
  );
}

export function SettingsPanel({ settings, onSave }: SettingsPanelProps) {
  const [draft, setDraft] = useState<AppSettings | null>(settings);
  const [portsInput, setPortsInput] = useState(settings ? formatPortsInput(settings.suspiciousPorts) : "");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(settings);
    setPortsInput(settings ? formatPortsInput(settings.suspiciousPorts) : "");
  }, [settings]);

  const parsedPorts = useMemo(() => parsePortsInput(portsInput), [portsInput]);
  const hasInvalidPorts = parsedPorts.invalidTokens.length > 0;

  const normalizedDraft = useMemo(() => {
    if (!draft || hasInvalidPorts) {
      return null;
    }

    return {
      ...draft,
      destinationProvider: draft.destinationProvider.trim(),
      reputationProvider: draft.reputationProvider.trim(),
      reputationApiKey: normalizeApiKey(draft.reputationApiKey),
      suspiciousPorts: parsedPorts.ports
    };
  }, [draft, hasInvalidPorts, parsedPorts.ports]);

  const hasChanges = useMemo(() => {
    if (!settings || !draft) {
      return false;
    }

    if (!normalizedDraft) {
      return portsInput.trim() !== formatPortsInput(settings.suspiciousPorts);
    }

    return !sameSettings(settings, normalizedDraft);
  }, [draft, normalizedDraft, portsInput, settings]);

  if (!draft) {
    return (
      <div className="panel settings-panel settings-panel--standalone settings-panel--refined">
        <div className="settings-hero">
          <div className="settings-hero__copy">
            <p className="eyebrow">Engine settings</p>
            <h2>Loading configuration</h2>
            <p className="panel__muted">
              Preparing the monitoring engine controls and trust policy.
            </p>
          </div>
        </div>
      </div>
    );
  }

  function patchDraft<Key extends keyof AppSettings>(key: Key, value: AppSettings[Key]) {
    setDraft((current) => (current ? { ...current, [key]: value } : current));
  }

  function resetDraft() {
    if (!settings) {
      return;
    }

    setDraft(settings);
    setPortsInput(formatPortsInput(settings.suspiciousPorts));
  }

  async function handleSave() {
    if (!normalizedDraft) {
      return;
    }

    setSaving(true);
    try {
      await onSave(normalizedDraft);
    } finally {
      setSaving(false);
    }
  }

  const saveHeadline = hasInvalidPorts
    ? "Fix the invalid ports before saving"
    : hasChanges
      ? "Changes pending"
      : "Settings in sync";

  const saveDetail = hasInvalidPorts
    ? `Review: ${parsedPorts.invalidTokens.join(", ")}`
    : hasChanges
      ? "Review the updated collection and detection policy, then save."
      : "The engine is using the values currently shown in this panel.";

  return (
    <div className="panel settings-panel settings-panel--standalone settings-panel--refined">
      <div className="settings-hero">
        <div className="settings-hero__copy">
          <p className="eyebrow">Engine settings</p>
          <h2>Collection and trust policy</h2>
          <p className="panel__muted">
            Tune the collection cadence, enrichment providers and detection defaults used by
            the monitoring engine.
          </p>
        </div>

        <div className="settings-hero__status">
          <span className={`settings-status-pill ${hasChanges ? "is-pending" : "is-synced"}`}>
            {hasChanges ? "Changes pending" : "Synced"}
          </span>
          <span className="settings-status-pill">
            {draft.enableDestinationEnrichment ? "Destination intel on" : "Destination intel off"}
          </span>
          <span className="settings-status-pill">
            {draft.enableReputation ? "Reputation on" : "Reputation off"}
          </span>
        </div>
      </div>

      <div className="settings-overview">
        <article className="settings-overview__card">
          <span className="detail-label">Collection cadence</span>
          <strong>{draft.pollingIntervalSecs}s</strong>
          <p>Polling interval for each live snapshot.</p>
        </article>
        <article className="settings-overview__card">
          <span className="detail-label">Retention window</span>
          <strong>{draft.retentionDays} days</strong>
          <p>How long activity and alerts remain available.</p>
        </article>
        <article className="settings-overview__card">
          <span className="detail-label">Alert cooldown</span>
          <strong>{draft.alertCooldownMinutes} min</strong>
          <p>Delay before the same alert pattern can fire again.</p>
        </article>
        <article className="settings-overview__card">
          <span className="detail-label">Watched ports</span>
          <strong>{parsedPorts.ports.length}</strong>
          <p>Ports that receive extra scrutiny in the classifier.</p>
        </article>
      </div>

      <div className="settings-layout">
        <section className="settings-card">
          <div className="settings-card__header">
            <div>
              <p className="eyebrow">Collection</p>
              <h3>Snapshot cadence</h3>
            </div>
            <span className="settings-card__badge">Core engine</span>
          </div>

          <div className="settings-card__grid">
            <label className="settings-field">
              <span className="settings-field__label">Polling interval</span>
              <span className="settings-field__hint">1 to 30 seconds between snapshots.</span>
              <input
                type="number"
                min={1}
                max={30}
                value={draft.pollingIntervalSecs}
                onChange={(event) => patchDraft("pollingIntervalSecs", Number(event.target.value))}
              />
            </label>

            <label className="settings-field">
              <span className="settings-field__label">Retention</span>
              <span className="settings-field__hint">1 to 365 days of stored activity.</span>
              <input
                type="number"
                min={1}
                max={365}
                value={draft.retentionDays}
                onChange={(event) => patchDraft("retentionDays", Number(event.target.value))}
              />
            </label>

            <label className="settings-field">
              <span className="settings-field__label">Baseline learning hits</span>
              <span className="settings-field__hint">
                How many repeats are needed before traffic feels familiar.
              </span>
              <input
                type="number"
                min={1}
                max={20}
                value={draft.baselineLearningThreshold}
                onChange={(event) =>
                  patchDraft("baselineLearningThreshold", Number(event.target.value))
                }
              />
            </label>

            <label className="settings-field">
              <span className="settings-field__label">Alert cooldown</span>
              <span className="settings-field__hint">
                1 to 240 minutes before reopening the same alert pattern.
              </span>
              <input
                type="number"
                min={1}
                max={240}
                value={draft.alertCooldownMinutes}
                onChange={(event) =>
                  patchDraft("alertCooldownMinutes", Number(event.target.value))
                }
              />
            </label>
          </div>
        </section>

        <section className="settings-card">
          <div className="settings-card__header">
            <div>
              <p className="eyebrow">Destination context</p>
              <h3>DNS and ASN enrichment</h3>
            </div>
            <span className="settings-card__badge">
              {draft.enableDestinationEnrichment ? "Enabled" : "Disabled"}
            </span>
          </div>

          <label
            className={`settings-toggle ${
              draft.enableDestinationEnrichment ? "is-enabled" : ""
            }`}
          >
            <span className="settings-toggle__copy">
              <span className="settings-toggle__label">Enable destination enrichment</span>
              <span className="settings-toggle__hint">
                Resolve hostname, ASN, organization and geographic context for remote endpoints.
              </span>
            </span>
            <span className="settings-toggle__control">
              <input
                type="checkbox"
                checked={draft.enableDestinationEnrichment}
                onChange={(event) =>
                  patchDraft("enableDestinationEnrichment", event.target.checked)
                }
              />
              <span>{draft.enableDestinationEnrichment ? "On" : "Off"}</span>
            </span>
          </label>

          <div className="settings-card__grid">
            <label className="settings-field">
              <span className="settings-field__label">Provider</span>
              <span className="settings-field__hint">
                Service or pipeline used for DNS and network ownership context.
              </span>
              <input
                type="text"
                value={draft.destinationProvider}
                onChange={(event) => patchDraft("destinationProvider", event.target.value)}
              />
            </label>

            <label className="settings-field">
              <span className="settings-field__label">Destination TTL</span>
              <span className="settings-field__hint">
                Cache lifetime in minutes for remote destination lookups.
              </span>
              <input
                type="number"
                min={5}
                max={10080}
                value={draft.destinationTtlMinutes}
                onChange={(event) =>
                  patchDraft("destinationTtlMinutes", Number(event.target.value))
                }
              />
            </label>
          </div>
        </section>

        <section className="settings-card">
          <div className="settings-card__header">
            <div>
              <p className="eyebrow">Reputation</p>
              <h3>External risk intelligence</h3>
            </div>
            <span className="settings-card__badge">
              {draft.enableReputation ? "Active lookup" : "Manual mode"}
            </span>
          </div>

          <label className={`settings-toggle ${draft.enableReputation ? "is-enabled" : ""}`}>
            <span className="settings-toggle__copy">
              <span className="settings-toggle__label">Enable IP reputation lookup</span>
              <span className="settings-toggle__hint">
                Query an external provider to enrich suspicious destinations with reputation data.
              </span>
            </span>
            <span className="settings-toggle__control">
              <input
                type="checkbox"
                checked={draft.enableReputation}
                onChange={(event) => patchDraft("enableReputation", event.target.checked)}
              />
              <span>{draft.enableReputation ? "On" : "Off"}</span>
            </span>
          </label>

          <div className="settings-card__grid">
            <label className="settings-field">
              <span className="settings-field__label">Provider</span>
              <span className="settings-field__hint">
                Reputation source used for IP scoring and verdicts.
              </span>
              <input
                type="text"
                value={draft.reputationProvider}
                onChange={(event) => patchDraft("reputationProvider", event.target.value)}
              />
            </label>

            <label className="settings-field">
              <span className="settings-field__label">Reputation TTL</span>
              <span className="settings-field__hint">
                Cache lifetime in minutes for reputation responses.
              </span>
              <input
                type="number"
                min={5}
                max={10080}
                value={draft.reputationTtlMinutes}
                onChange={(event) =>
                  patchDraft("reputationTtlMinutes", Number(event.target.value))
                }
              />
            </label>

            <label className="settings-field settings-field--wide">
              <span className="settings-field__label">API key</span>
              <span className="settings-field__hint">
                Optional. Leave empty to keep reputation lookups disabled or unauthenticated.
              </span>
              <input
                type="password"
                placeholder="Optional"
                value={draft.reputationApiKey ?? ""}
                onChange={(event) =>
                  patchDraft("reputationApiKey", event.target.value || null)
                }
              />
            </label>
          </div>
        </section>

        <section className="settings-card">
          <div className="settings-card__header">
            <div>
              <p className="eyebrow">Detection policy</p>
              <h3>Classifier defaults</h3>
            </div>
            <span className="settings-card__badge">Analyst tuned</span>
          </div>

          <div className="settings-card__grid">
            <label className="settings-field settings-field--wide">
              <span className="settings-field__label">Suspicious ports watchlist</span>
              <span className="settings-field__hint">
                Comma-separated TCP or UDP ports that should be treated with extra scrutiny.
              </span>
              <input
                type="text"
                value={portsInput}
                onChange={(event) => setPortsInput(event.target.value)}
                placeholder="22, 23, 135, 139, 445, 3389"
              />
            </label>
          </div>

          <div className="settings-note-grid">
            <div className="settings-note">
              <span className="detail-label">Port parsing</span>
              <strong>{hasInvalidPorts ? "Needs review" : "Ready to save"}</strong>
              <p>
                {hasInvalidPorts
                  ? `Invalid entries: ${parsedPorts.invalidTokens.join(", ")}`
                  : `${parsedPorts.ports.length} unique ports configured.`}
              </p>
            </div>
            <div className="settings-note">
              <span className="detail-label">API key status</span>
              <strong>{draft.reputationApiKey ? "Loaded" : "Not configured"}</strong>
              <p>
                {draft.reputationApiKey
                  ? "A reputation key is present for authenticated lookups."
                  : "You can keep this blank if external reputation is not required."}
              </p>
            </div>
          </div>
        </section>
      </div>

      <div className="settings-savebar">
        <div className="settings-savebar__copy">
          <strong>{saveHeadline}</strong>
          <span>{saveDetail}</span>
        </div>

        <div className="settings-savebar__actions">
          <button
            type="button"
            className="action-button"
            onClick={resetDraft}
            disabled={saving || !hasChanges}
          >
            Reset changes
          </button>
          <button
            type="button"
            className="action-button action-button--primary"
            onClick={() => void handleSave()}
            disabled={saving || !hasChanges || hasInvalidPorts}
          >
            {saving ? "Saving..." : "Save settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
