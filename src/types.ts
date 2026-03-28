export type RiskLevel = "safe" | "unknown" | "suspicious";

export interface RiskReason {
  code: string;
  message: string;
}

export interface ReputationInfo {
  source: string;
  verdict: string;
  score: number | null;
  summary: string;
  checkedAt: string;
}

export interface ProcessIdentity {
  pid: number;
  name: string;
  exePath: string | null;
  user: string | null;
  parentPid: number | null;
  parentName: string | null;
  signer: string | null;
  isSigned: boolean;
  publisher: string | null;
  sha256: string | null;
  metadataPending: boolean;
  hostedServices: string[];
  serviceContextPending: boolean;
}

export interface ConnectionEvent {
  id: string;
  timestamp: string;
  protocol: string;
  direction: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
  state: string;
  pid: number;
  process: ProcessIdentity;
  riskLevel: RiskLevel;
  score: number;
  confidence: number;
  baselineHits: number;
  reasons: RiskReason[];
  reputation: ReputationInfo | null;
  suggestedFirewallRule: string | null;
  isNew: boolean;
}

export interface AlertRecord {
  id: string;
  alertKey: string;
  connectionEventId: string;
  riskLevel: RiskLevel;
  score: number;
  confidence: number;
  reasons: RiskReason[];
  recommendedAction: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  occurrenceCount: number;
  connection: ConnectionEvent | null;
}

export interface AllowRule {
  id: string;
  label: string;
  processName: string | null;
  signer: string | null;
  exePath: string | null;
  sha256: string | null;
  remotePattern: string | null;
  port: number | null;
  protocol: string | null;
  direction: string | null;
  createdAt: string;
}

export interface AppSettings {
  pollingIntervalSecs: number;
  retentionDays: number;
  baselineLearningThreshold: number;
  alertCooldownMinutes: number;
  enableReputation: boolean;
  reputationProvider: string;
  reputationApiKey: string | null;
  reputationTtlMinutes: number;
  suspiciousPorts: number[];
}

export interface AlertFilters {
  statuses?: string[];
  riskLevels?: RiskLevel[];
  limit?: number;
}

export interface SummaryStats {
  safe: number;
  unknown: number;
  suspicious: number;
  total: number;
}

export interface ActivityEvent {
  id: string;
  timestamp: string;
  changeType: string;
  connection: ConnectionEvent;
}

export interface MonitorUpdate {
  connections: ConnectionEvent[];
  alerts: AlertRecord[];
  activity: ActivityEvent[];
  removedConnectionIds: string[];
  summary: SummaryStats;
  collectedAt: string;
}

export type ConnectionCommandAction =
  | "view_process"
  | "get_executable_path"
  | "check_svchost_services"
  | "get_svchost_service_details";

export interface ConnectionCommandRequest {
  action: ConnectionCommandAction;
  pid: number;
  processName: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
}

export interface CommandExecutionResult {
  title: string;
  command: string;
  output: string;
  success: boolean;
  executedAt: string;
}
