import { useState } from "react";
import { getEstablishedConnections } from "../lib/tauri";
import type { CommandExecutionResult } from "../types";

export function useEstablishedReport() {
  const [establishedResult, setEstablishedResult] = useState<CommandExecutionResult | null>(
    null
  );
  const [establishedOpen, setEstablishedOpen] = useState(false);
  const [establishedLoading, setEstablishedLoading] = useState(false);
  const [establishedError, setEstablishedError] = useState<string | null>(null);

  async function handleRefreshEstablishedConnections() {
    setEstablishedLoading(true);
    setEstablishedError(null);
    try {
      const result = await getEstablishedConnections();
      setEstablishedResult(result);
    } catch (cause) {
      setEstablishedError(
        cause instanceof Error ? cause.message : "Failed to fetch established connections"
      );
    } finally {
      setEstablishedLoading(false);
    }
  }

  async function handleOpenEstablishedConnections() {
    setEstablishedOpen(true);
    if (establishedLoading) {
      return;
    }
    await handleRefreshEstablishedConnections();
  }

  function handleCloseEstablishedConnections() {
    setEstablishedOpen(false);
  }

  return {
    establishedResult,
    establishedOpen,
    establishedLoading,
    establishedError,
    handleRefreshEstablishedConnections,
    handleOpenEstablishedConnections,
    handleCloseEstablishedConnections
  };
}
