import { useEffect, useState } from "react";
import type { AppSettings } from "../types";

interface SettingsPanelProps {
  settings: AppSettings | null;
  onSave: (settings: AppSettings) => Promise<void>;
}

export function SettingsPanel({ settings, onSave }: SettingsPanelProps) {
  const [draft, setDraft] = useState<AppSettings | null>(settings);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(settings);
  }, [settings]);

  if (!draft) {
    return (
      <div className="panel settings-panel settings-panel--standalone">
        <p className="eyebrow">Engine settings</p>
        <h2>Loading settings</h2>
      </div>
    );
  }

  async function handleSave() {
    if (!draft) {
      return;
    }

    const activeDraft = draft;
    setSaving(true);
    try {
      await onSave(activeDraft);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="panel settings-panel settings-panel--standalone">
      <div className="panel__header">
        <div>
          <p className="eyebrow">Engine settings</p>
          <h2>Collection and trust policy</h2>
        </div>
      </div>

      <div className="settings-grid">
        <label>
          Polling interval (seconds)
          <input
            type="number"
            min={1}
            max={30}
            value={draft.pollingIntervalSecs}
            onChange={(event) =>
              setDraft({
                ...draft,
                pollingIntervalSecs: Number(event.target.value)
              })
            }
          />
        </label>
        <label>
          Retention (days)
          <input
            type="number"
            min={1}
            max={365}
            value={draft.retentionDays}
            onChange={(event) =>
              setDraft({
                ...draft,
                retentionDays: Number(event.target.value)
              })
            }
          />
        </label>
        <label>
          Baseline learning hits
          <input
            type="number"
            min={1}
            max={20}
            value={draft.baselineLearningThreshold}
            onChange={(event) =>
              setDraft({
                ...draft,
                baselineLearningThreshold: Number(event.target.value)
              })
            }
          />
        </label>
        <label>
          Alert cooldown (minutes)
          <input
            type="number"
            min={1}
            max={240}
            value={draft.alertCooldownMinutes}
            onChange={(event) =>
              setDraft({
                ...draft,
                alertCooldownMinutes: Number(event.target.value)
              })
            }
          />
        </label>
        <label className="settings-grid__wide settings-grid__toggle">
          <span>Enable DNS and ASN enrichment</span>
          <input
            type="checkbox"
            checked={draft.enableDestinationEnrichment}
            onChange={(event) =>
              setDraft({
                ...draft,
                enableDestinationEnrichment: event.target.checked
              })
            }
          />
        </label>
        <label>
          Enrichment provider
          <input
            type="text"
            value={draft.destinationProvider}
            onChange={(event) =>
              setDraft({
                ...draft,
                destinationProvider: event.target.value
              })
            }
          />
        </label>
        <label>
          Enrichment TTL (minutes)
          <input
            type="number"
            min={5}
            max={10080}
            value={draft.destinationTtlMinutes}
            onChange={(event) =>
              setDraft({
                ...draft,
                destinationTtlMinutes: Number(event.target.value)
              })
            }
          />
        </label>
        <label className="settings-grid__wide settings-grid__toggle">
          <span>Enable IP reputation lookup</span>
          <input
            type="checkbox"
            checked={draft.enableReputation}
            onChange={(event) =>
              setDraft({
                ...draft,
                enableReputation: event.target.checked
              })
            }
          />
        </label>
        <label>
          Provider
          <input
            type="text"
            value={draft.reputationProvider}
            onChange={(event) =>
              setDraft({
                ...draft,
                reputationProvider: event.target.value
              })
            }
          />
        </label>
        <label className="settings-grid__wide">
          API key
          <input
            type="password"
            placeholder="Optional"
            value={draft.reputationApiKey ?? ""}
            onChange={(event) =>
              setDraft({
                ...draft,
                reputationApiKey: event.target.value || null
              })
            }
          />
        </label>
      </div>

      <button
        type="button"
        className="action-button action-button--primary"
        onClick={() => void handleSave()}
        disabled={saving}
      >
        {saving ? "Saving..." : "Save settings"}
      </button>
    </div>
  );
}
