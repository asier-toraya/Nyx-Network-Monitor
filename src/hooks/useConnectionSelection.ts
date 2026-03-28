import { useEffect, useState } from "react";
import { getAlertDetails } from "../lib/tauri";
import type { SelectedConnectionSource } from "../lib/monitoring";
import type { ActivityEvent, AlertRecord, ConnectionEvent } from "../types";

interface UseConnectionSelectionOptions {
  alerts: AlertRecord[];
  liveConnections: ConnectionEvent[];
  escapeActive: boolean;
  onEscape: () => void;
}

export function useConnectionSelection({
  alerts,
  liveConnections,
  escapeActive,
  onEscape
}: UseConnectionSelectionOptions) {
  const [selectedConnection, setSelectedConnection] = useState<ConnectionEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [selectedConnectionSource, setSelectedConnectionSource] =
    useState<SelectedConnectionSource>(null);
  const [selectedActivityId, setSelectedActivityId] = useState<string | null>(null);

  const selectedLiveConnectionId =
    selectedConnectionSource === "live" ? selectedConnection?.id ?? null : null;

  function clearSelection() {
    setSelectedConnection(null);
    setSelectedAlert(null);
    setSelectedConnectionSource(null);
    setSelectedActivityId(null);
  }

  function handleCloseDetails() {
    clearSelection();
  }

  function handleSelectLiveConnection(connection: ConnectionEvent) {
    setSelectedConnection(connection);
    setSelectedConnectionSource("live");
    setSelectedActivityId(null);
    const alert = alerts.find((entry) => entry.connectionEventId === connection.id) ?? null;
    setSelectedAlert(alert);
  }

  function handleSelectHistoryEvent(event: ActivityEvent) {
    setSelectedConnection(event.connection);
    setSelectedConnectionSource("history");
    setSelectedActivityId(event.id);
    const alert = alerts.find((entry) => entry.connectionEventId === event.connection.id) ?? null;
    setSelectedAlert(alert);
  }

  async function handleSelectAlert(alert: AlertRecord) {
    setSelectedAlert(alert);
    setSelectedConnectionSource("live");
    setSelectedActivityId(null);

    if (alert.connection) {
      setSelectedConnection(alert.connection);
      return;
    }

    const detailed = await getAlertDetails(alert.id);
    setSelectedAlert(detailed);
    setSelectedConnection(detailed.connection);
  }

  function handleDismissedAlert(alertId: string) {
    setSelectedAlert((current) => (current?.id === alertId ? null : current));
  }

  useEffect(() => {
    if (!selectedConnection || selectedConnectionSource !== "live") {
      return;
    }

    const stillExists = liveConnections.some(
      (connection) => connection.id === selectedConnection.id
    );

    if (!stillExists) {
      clearSelection();
    }
  }, [liveConnections, selectedConnection, selectedConnectionSource]);

  useEffect(() => {
    if (!selectedConnection && !escapeActive) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        handleCloseDetails();
        onEscape();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [escapeActive, onEscape, selectedConnection]);

  return {
    selectedConnection,
    selectedAlert,
    selectedActivityId,
    selectedLiveConnectionId,
    handleCloseDetails,
    handleSelectLiveConnection,
    handleSelectHistoryEvent,
    handleSelectAlert,
    handleDismissedAlert
  };
}
