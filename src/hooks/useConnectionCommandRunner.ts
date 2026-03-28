import { useEffect, useState } from "react";
import { executeConnectionCommand } from "../lib/tauri";
import type {
  CommandExecutionResult,
  ConnectionCommandAction,
  ConnectionEvent
} from "../types";

export function useConnectionCommandRunner(connection: ConnectionEvent | null) {
  const [commandResult, setCommandResult] = useState<CommandExecutionResult | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);
  const [runningAction, setRunningAction] = useState<ConnectionCommandAction | null>(null);

  useEffect(() => {
    setCommandResult(null);
    setCommandError(null);
    setRunningAction(null);
  }, [connection?.id]);

  async function handleRunAction(action: ConnectionCommandAction) {
    if (!connection) {
      return;
    }

    setRunningAction(action);
    setCommandError(null);

    try {
      const result = await executeConnectionCommand({
        action,
        pid: connection.pid,
        processName: connection.process.name,
        localAddress: connection.localAddress,
        localPort: connection.localPort,
        remoteAddress: connection.remoteAddress,
        remotePort: connection.remotePort
      });

      setCommandResult(result);
    } catch (cause) {
      setCommandError(
        cause instanceof Error ? cause.message : "Failed to execute the requested command"
      );
    } finally {
      setRunningAction(null);
    }
  }

  return {
    commandResult,
    commandError,
    runningAction,
    handleRunAction
  };
}
