use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Safe,
    Unknown,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RiskReason {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReputationInfo {
    pub source: String,
    pub verdict: String,
    pub score: Option<i32>,
    pub summary: String,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub exe_path: Option<String>,
    pub user: Option<String>,
    #[serde(default)]
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub parent_name: Option<String>,
    pub signer: Option<String>,
    pub is_signed: bool,
    pub publisher: Option<String>,
    pub sha256: Option<String>,
    #[serde(default)]
    pub metadata_pending: bool,
    #[serde(default)]
    pub hosted_services: Vec<String>,
    #[serde(default)]
    pub service_context_pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub protocol: String,
    pub direction: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: u32,
    pub process: ProcessIdentity,
    pub risk_level: RiskLevel,
    pub score: i32,
    pub confidence: i32,
    pub baseline_hits: u32,
    pub reasons: Vec<RiskReason>,
    pub reputation: Option<ReputationInfo>,
    pub suggested_firewall_rule: Option<String>,
    pub is_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlertRecord {
    pub id: String,
    pub alert_key: String,
    pub connection_event_id: String,
    pub risk_level: RiskLevel,
    pub score: i32,
    pub confidence: i32,
    pub reasons: Vec<RiskReason>,
    pub recommended_action: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub occurrence_count: u32,
    pub connection: Option<ConnectionEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AllowRule {
    pub id: String,
    pub label: String,
    pub process_name: Option<String>,
    pub signer: Option<String>,
    pub exe_path: Option<String>,
    pub sha256: Option<String>,
    pub remote_pattern: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AllowRuleInput {
    pub label: Option<String>,
    pub process_name: Option<String>,
    pub signer: Option<String>,
    pub exe_path: Option<String>,
    pub sha256: Option<String>,
    pub remote_pattern: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AlertFilters {
    pub statuses: Option<Vec<String>>,
    pub risk_levels: Option<Vec<RiskLevel>>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub polling_interval_secs: u64,
    pub retention_days: u32,
    pub baseline_learning_threshold: u32,
    pub alert_cooldown_minutes: u64,
    pub enable_reputation: bool,
    pub reputation_provider: String,
    pub reputation_api_key: Option<String>,
    pub reputation_ttl_minutes: u64,
    pub suspicious_ports: Vec<u16>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            polling_interval_secs: 2,
            retention_days: 30,
            baseline_learning_threshold: 3,
            alert_cooldown_minutes: 20,
            enable_reputation: false,
            reputation_provider: "abuseipdb".to_string(),
            reputation_api_key: None,
            reputation_ttl_minutes: 1_440,
            suspicious_ports: vec![22, 23, 135, 139, 445, 3389, 5900, 5985, 5986],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SummaryStats {
    pub safe: usize,
    pub unknown: usize,
    pub suspicious: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub change_type: String,
    pub connection: ConnectionEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MonitorUpdate {
    pub connections: Vec<ConnectionEvent>,
    pub alerts: Vec<AlertRecord>,
    pub activity: Vec<ActivityEvent>,
    pub removed_connection_ids: Vec<String>,
    pub summary: SummaryStats,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSnapshot {
    pub id: String,
    pub protocol: String,
    pub direction: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassificationResult {
    pub risk_level: RiskLevel,
    pub score: i32,
    pub confidence: i32,
    pub reasons: Vec<RiskReason>,
    pub recommended_action: String,
    pub suggested_firewall_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficBaseline {
    pub pattern_key: String,
    pub summary: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCommandAction {
    ViewProcess,
    GetExecutablePath,
    CheckSvchostServices,
    GetSvchostServiceDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionCommandRequest {
    pub action: ConnectionCommandAction,
    pub pid: u32,
    pub process_name: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommandExecutionResult {
    pub title: String,
    pub command: String,
    pub output: String,
    pub success: bool,
    pub executed_at: DateTime<Utc>,
}
