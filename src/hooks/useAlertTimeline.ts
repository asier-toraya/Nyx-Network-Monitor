import { useEffect, useState } from "react";
import { getAlertTimeline } from "../lib/tauri";
import type { AlertTimelineEvent } from "../types";

export function useAlertTimeline(alertId: string | null | undefined, limit = 20) {
  const [alertTimeline, setAlertTimeline] = useState<AlertTimelineEvent[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);

  useEffect(() => {
    if (!alertId) {
      setAlertTimeline([]);
      setTimelineError(null);
      setTimelineLoading(false);
      return;
    }

    let disposed = false;
    setTimelineLoading(true);
    setTimelineError(null);

    void getAlertTimeline(alertId, limit)
      .then((events) => {
        if (!disposed) {
          setAlertTimeline(events);
        }
      })
      .catch((cause) => {
        if (!disposed) {
          setTimelineError(
            cause instanceof Error ? cause.message : "Failed to load alert timeline"
          );
        }
      })
      .finally(() => {
        if (!disposed) {
          setTimelineLoading(false);
        }
      });

    return () => {
      disposed = true;
    };
  }, [alertId, limit]);

  return {
    alertTimeline,
    timelineLoading,
    timelineError
  };
}
