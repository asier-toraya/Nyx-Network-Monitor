import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  ActivityEvent,
  AlertFilters,
  AlertRecord,
  AllowRule,
  AppSettings,
  CommandExecutionResult,
  ConnectionCommandRequest,
  ConnectionEvent,
  MonitorUpdate
} from "../types";

export async function getLiveConnections(): Promise<ConnectionEvent[]> {
  return invoke("get_live_connections");
}

export async function subscribeConnectionEvents(
  onUpdate: (update: MonitorUpdate) => void
): Promise<UnlistenFn> {
  await invoke("subscribe_connection_events");
  return listen<MonitorUpdate>("monitor://connection", (event) => onUpdate(event.payload));
}

export async function getAlerts(filters: AlertFilters = {}): Promise<AlertRecord[]> {
  return invoke("get_alerts", { filters });
}

export async function getAlertDetails(id: string): Promise<AlertRecord> {
  return invoke("get_alert_details", { id });
}

export async function listAllowRules(): Promise<AllowRule[]> {
  return invoke("list_allow_rules");
}

export async function createAllowRule(rule: Partial<AllowRule>): Promise<AllowRule> {
  return invoke("create_allow_rule", { rule });
}

export async function dismissAlert(id: string): Promise<void> {
  return invoke("dismiss_alert", { id });
}

export async function getSettings(): Promise<AppSettings> {
  return invoke("get_settings");
}

export async function updateSettings(settings: AppSettings): Promise<AppSettings> {
  return invoke("update_settings", { settings });
}

export async function getEstablishedConnections(): Promise<CommandExecutionResult> {
  return invoke("get_established_connections");
}

export async function getRecentActivity(limit?: number): Promise<ActivityEvent[]> {
  return invoke("get_recent_activity", { limit });
}

export async function deleteAllowRule(id: string): Promise<void> {
  return invoke("delete_allow_rule", { id });
}

export async function executeConnectionCommand(
  request: ConnectionCommandRequest
): Promise<CommandExecutionResult> {
  return invoke("execute_connection_command", { request });
}
