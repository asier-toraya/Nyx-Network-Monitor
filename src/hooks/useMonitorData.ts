import { startTransition, useEffect, useState } from "react";
import {
  getAlerts,
  getLiveConnections,
  getRecentActivity,
  getSettings,
  listAllowRules,
  subscribeConnectionEvents
} from "../lib/tauri";
import {
  ACTIVITY_LIMIT,
  RECONCILE_INTERVAL_MS,
  mergeActivity,
  mergeAlerts,
  mergeConnections,
  sortConnections
} from "../lib/monitoring";
import type {
  ActivityEvent,
  AlertRecord,
  AllowRule,
  AppSettings,
  ConnectionEvent
} from "../types";

export function useMonitorData() {
  const [connections, setConnections] = useState<ConnectionEvent[]>([]);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [allowRules, setAllowRules] = useState<AllowRule[]>([]);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | undefined;

    async function bootstrap() {
      try {
        unlisten = await subscribeConnectionEvents((update) => {
          startTransition(() => {
            setConnections((current) =>
              mergeConnections(current, update.connections, update.removedConnectionIds)
            );
            setAlerts((current) => mergeAlerts(current, update.alerts));
            setActivity((current) => mergeActivity(current, update.activity));
            setLastRefresh(update.collectedAt);
          });
        });

        const [live, alertRows, rules, savedSettings, recentActivity] = await Promise.all([
          getLiveConnections(),
          getAlerts({ statuses: ["open", "new"], limit: 100 }),
          listAllowRules(),
          getSettings(),
          getRecentActivity(ACTIVITY_LIMIT)
        ]);

        if (disposed) {
          return;
        }

        startTransition(() => {
          setConnections((current) => mergeConnections(live, current));
          setAlerts((current) => mergeAlerts(alertRows, current));
          setActivity((current) => mergeActivity(recentActivity, current));
          setAllowRules(rules);
          setSettings(savedSettings);
          setLastRefresh(new Date().toISOString());
        });
      } catch (cause) {
        if (!disposed) {
          setError(cause instanceof Error ? cause.message : "Failed to load app state");
        }
      }
    }

    void bootstrap();

    return () => {
      disposed = true;
      if (unlisten) {
        void unlisten();
      }
    };
  }, []);

  useEffect(() => {
    let disposed = false;

    const interval = window.setInterval(() => {
      void (async () => {
        try {
          const [live, alertRows, recentActivity] = await Promise.all([
            getLiveConnections(),
            getAlerts({ statuses: ["open", "new"], limit: 100 }),
            getRecentActivity(ACTIVITY_LIMIT)
          ]);

          if (disposed) {
            return;
          }

          startTransition(() => {
            setConnections(sortConnections(live));
            setAlerts(mergeAlerts([], alertRows));
            setActivity(mergeActivity([], recentActivity));
            setLastRefresh(new Date().toISOString());
          });
        } catch {
          // Keep the monitor running on the last good snapshot if reconciliation fails.
        }
      })();
    }, RECONCILE_INTERVAL_MS);

    return () => {
      disposed = true;
      window.clearInterval(interval);
    };
  }, []);

  return {
    connections,
    alerts,
    activity,
    allowRules,
    settings,
    lastRefresh,
    error,
    setAlerts,
    setAllowRules,
    setSettings
  };
}
