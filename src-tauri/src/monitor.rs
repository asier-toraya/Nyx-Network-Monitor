use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::Context;
use chrono::{Duration as ChronoDuration, Utc};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use parking_lot::RwLock;
use sysinfo::{ProcessesToUpdate, System};
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

use crate::{
    classifier::classify_connection,
    db::Database,
    destination::resolve_destination,
    models::{
        ActivityEvent, AlertRecord, AllowRule, AppSettings, ConnectionEvent, MonitorUpdate,
        RiskLevel, SocketSnapshot, SummaryStats, TrafficBaseline,
    },
    process_info::ProcessEnricher,
    reputation::resolve_reputation,
};

#[derive(Clone)]
pub struct AppState {
    pub database: Database,
    pub live_connections: Arc<RwLock<HashMap<String, ConnectionEvent>>>,
    pub allow_rules: Arc<RwLock<Vec<AllowRule>>>,
    pub settings: Arc<RwLock<AppSettings>>,
    pub process_enricher: Arc<ProcessEnricher>,
    pub baseline_cache: Arc<RwLock<HashMap<String, TrafficBaseline>>>,
    pub active_alerts: Arc<RwLock<HashMap<String, AlertRecord>>>,
}

impl AppState {
    pub fn new(
        database: Database,
        allow_rules: Vec<AllowRule>,
        settings: AppSettings,
        baselines: Vec<TrafficBaseline>,
        active_alerts: Vec<AlertRecord>,
    ) -> Self {
        Self {
            database,
            live_connections: Arc::new(RwLock::new(HashMap::new())),
            allow_rules: Arc::new(RwLock::new(allow_rules)),
            settings: Arc::new(RwLock::new(settings)),
            process_enricher: Arc::new(ProcessEnricher::default()),
            baseline_cache: Arc::new(RwLock::new(
                baselines
                    .into_iter()
                    .map(|entry| (entry.pattern_key.clone(), entry))
                    .collect(),
            )),
            active_alerts: Arc::new(RwLock::new(
                active_alerts
                    .into_iter()
                    .map(|entry| (entry.alert_key.clone(), entry))
                    .collect(),
            )),
        }
    }
}

pub fn start_monitor(app: AppHandle, state: AppState) {
    thread::spawn(move || {
        let mut previous = HashMap::<String, ConnectionEvent>::new();
        let mut system = System::new();
        let mut tick_counter: u64 = 0;

        loop {
            let settings = state.settings.read().clone();
            let allow_rules = state.allow_rules.read().clone();

            match poll_once(&app, &state, &mut previous, &mut system, &settings, &allow_rules) {
                Ok(()) => {}
                Err(error) => {
                    eprintln!("sentinel-desk poll failed: {error:#}");
                }
            }

            tick_counter += 1;
            if tick_counter % 30 == 0 {
                let _ = state.database.prune(settings.retention_days);
            }

            thread::sleep(Duration::from_secs(settings.polling_interval_secs.max(1)));
        }
    });
}

fn poll_once(
    app: &AppHandle,
    state: &AppState,
    previous: &mut HashMap<String, ConnectionEvent>,
    system: &mut System,
    settings: &AppSettings,
    allow_rules: &[AllowRule],
) -> anyhow::Result<()> {
    system.refresh_processes(ProcessesToUpdate::All, true);
    let now = Utc::now();
    let sockets = collect_socket_snapshots().context("collecting socket snapshots")?;
    let mut current = HashMap::<String, ConnectionEvent>::new();
    let mut changed_connections = Vec::<ConnectionEvent>::new();
    let mut changed_alerts = Vec::<AlertRecord>::new();
    let mut activity_events = Vec::<ActivityEvent>::new();
    let mut touched_patterns = HashMap::<String, String>::new();

    for socket in sockets {
        let process = state.process_enricher.resolve_process(system, socket.pid);
        let baseline_key = build_pattern_key(&socket, &process);
        let alert_key = build_alert_key(&socket, &process);
        let baseline = state.baseline_cache.read().get(&baseline_key).cloned();
        let destination = resolve_destination(&state.database, settings, socket.remote_address.as_deref());
        let reputation = resolve_reputation(&state.database, settings, socket.remote_address.as_deref());
        let classified = classify_connection(
            &socket,
            &process,
            reputation.as_ref(),
            baseline.as_ref(),
            allow_rules,
            settings,
        );

        let baseline_hits = baseline.as_ref().map(|entry| entry.hit_count).unwrap_or(0);
        let is_new_connection = !previous.contains_key(&socket.id);
        let changed = previous
            .get(&socket.id)
            .map(|existing| {
                existing.state != socket.state
                    || existing.risk_level != classified.risk_level
                    || existing.score != classified.score
                    || existing.confidence != classified.confidence
                    || existing.baseline_hits != baseline_hits
                    || existing.process != process
                    || existing.destination != destination
                    || existing.reputation != reputation
                    || existing.reasons != classified.reasons
            })
            .unwrap_or(true);
        let significant_change = previous
            .get(&socket.id)
            .map(|existing| {
                existing.state != socket.state
                    || existing.direction != socket.direction
                    || existing.risk_level != classified.risk_level
                    || existing.score != classified.score
                    || existing.remote_address != socket.remote_address
                    || existing.remote_port != socket.remote_port
                    || existing.destination != destination
            })
            .unwrap_or(true);

        let event = ConnectionEvent {
            id: socket.id.clone(),
            timestamp: now,
            protocol: socket.protocol.clone(),
            direction: socket.direction.clone(),
            local_address: socket.local_address.clone(),
            local_port: socket.local_port,
            remote_address: socket.remote_address.clone(),
            remote_port: socket.remote_port,
            state: socket.state.clone(),
            pid: socket.pid,
            process,
            risk_level: classified.risk_level.clone(),
            score: classified.score,
            confidence: classified.confidence,
            baseline_hits,
            reasons: classified.reasons.clone(),
            reputation: reputation.clone(),
            destination: destination.clone(),
            suggested_firewall_rule: classified.suggested_firewall_rule.clone(),
            is_new: is_new_connection,
        };

        if changed {
            state.database.save_connection_event(&event)?;
            if significant_change {
                let activity_event = build_activity_event(
                    &event,
                    if is_new_connection { "opened" } else { "updated" },
                    now,
                );
                state.database.append_activity_event(&activity_event)?;
                activity_events.push(activity_event);
            }
        }

        touched_patterns
            .entry(baseline_key.clone())
            .or_insert_with(|| build_pattern_summary(&socket, &event.process));

        let alert = if significant_change && event.risk_level != RiskLevel::Safe {
            let alert = upsert_alert(state, &event, &alert_key, classified.recommended_action, now, settings)?;
            Some(alert)
        } else {
            None
        };

        if changed {
            changed_connections.push(event.clone());
            if let Some(alert) = alert {
                changed_alerts.push(alert);
            }
        }

        current.insert(event.id.clone(), event);
    }

    if !touched_patterns.is_empty() {
        let mut baseline_cache = state.baseline_cache.write();
        for (pattern_key, summary) in touched_patterns {
            let baseline_entry = state.database.touch_baseline(&pattern_key, &summary, now)?;
            baseline_cache.insert(pattern_key, baseline_entry);
        }
    }

    let removed_ids = previous
        .keys()
        .filter(|id| !current.contains_key(*id))
        .cloned()
        .collect::<Vec<_>>();

    for removed_id in &removed_ids {
        if let Some(previous_connection) = previous.get(removed_id) {
            let activity_event = build_activity_event(previous_connection, "closed", now);
            state.database.append_activity_event(&activity_event)?;
            activity_events.push(activity_event);
        }
    }

    let summary = summarize(&current);
    {
        let mut live = state.live_connections.write();
        *live = current.clone();
    }

    let update = MonitorUpdate {
        connections: changed_connections,
        alerts: changed_alerts,
        activity: activity_events,
        removed_connection_ids: removed_ids,
        summary,
        collected_at: now,
    };
    let _ = app.emit("monitor://connection", update);

    *previous = current;
    Ok(())
}

fn upsert_alert(
    state: &AppState,
    event: &ConnectionEvent,
    alert_key: &str,
    recommended_action: String,
    now: chrono::DateTime<Utc>,
    settings: &AppSettings,
) -> anyhow::Result<AlertRecord> {
    let cooldown = ChronoDuration::minutes(settings.alert_cooldown_minutes as i64);
    let existing_alert = state.active_alerts.read().get(alert_key).cloned();

    let alert = if let Some(existing) = existing_alert.as_ref() {
        let same_window = now - existing.updated_at < cooldown;
        let escalated = matches!(
            (&existing.risk_level, &event.risk_level),
            (RiskLevel::Unknown, RiskLevel::Suspicious)
        );

        AlertRecord {
            id: existing.id.clone(),
            alert_key: alert_key.to_string(),
            connection_event_id: event.id.clone(),
            risk_level: if escalated {
                event.risk_level.clone()
            } else {
                existing.risk_level.clone()
            },
            score: existing.score.max(event.score),
            confidence: existing.confidence.max(event.confidence),
            reasons: event.reasons.clone(),
            recommended_action: if same_window && !escalated {
                existing.recommended_action.clone()
            } else {
                recommended_action
            },
            status: if existing.status == "new" && same_window {
                "open".to_string()
            } else {
                existing.status.clone()
            },
            created_at: existing.created_at,
            updated_at: now,
            occurrence_count: existing.occurrence_count + 1,
            connection: Some(event.clone()),
        }
    } else {
        AlertRecord {
            id: Uuid::new_v4().to_string(),
            alert_key: alert_key.to_string(),
            connection_event_id: event.id.clone(),
            risk_level: event.risk_level.clone(),
            score: event.score,
            confidence: event.confidence,
            reasons: event.reasons.clone(),
            recommended_action,
            status: "new".to_string(),
            created_at: now,
            updated_at: now,
            occurrence_count: 1,
            connection: Some(event.clone()),
        }
    };

    state.database.save_alert(&alert)?;
    let timeline_event = build_alert_timeline_event(&alert, existing_alert.as_ref(), now);
    let _ = state.database.append_alert_timeline_event(&timeline_event);
    state
        .active_alerts
        .write()
        .insert(alert_key.to_string(), alert.clone());
    Ok(alert)
}

fn summarize(connections: &HashMap<String, ConnectionEvent>) -> SummaryStats {
    let mut summary = SummaryStats::default();
    summary.total = connections.len();
    for connection in connections.values() {
        match connection.risk_level {
            RiskLevel::Safe => summary.safe += 1,
            RiskLevel::Unknown => summary.unknown += 1,
            RiskLevel::Suspicious => summary.suspicious += 1,
        }
    }
    summary
}

pub fn collect_socket_snapshots() -> anyhow::Result<Vec<SocketSnapshot>> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )?;
    let mut snapshots = Vec::new();

    for socket in sockets {
        let pid = socket.associated_pids.first().copied().unwrap_or_default();
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                let direction = infer_tcp_direction(tcp.state, tcp.local_port, tcp.remote_port);
                let remote_address = if tcp.remote_addr.is_unspecified() {
                    None
                } else {
                    Some(tcp.remote_addr.to_string())
                };
                let remote_port = if tcp.remote_port == 0 { None } else { Some(tcp.remote_port) };
                let id = make_snapshot_id(
                    "tcp",
                    pid,
                    &tcp.local_addr.to_string(),
                    tcp.local_port,
                    remote_address.as_deref(),
                    remote_port,
                );
                snapshots.push(SocketSnapshot {
                    id,
                    protocol: "tcp".to_string(),
                    direction,
                    local_address: tcp.local_addr.to_string(),
                    local_port: tcp.local_port,
                    remote_address,
                    remote_port,
                    state: format!("{:?}", tcp.state),
                    pid,
                });
            }
            ProtocolSocketInfo::Udp(udp) => {
                let id = make_snapshot_id(
                    "udp",
                    pid,
                    &udp.local_addr.to_string(),
                    udp.local_port,
                    None,
                    None,
                );
                snapshots.push(SocketSnapshot {
                    id,
                    protocol: "udp".to_string(),
                    direction: "listening".to_string(),
                    local_address: udp.local_addr.to_string(),
                    local_port: udp.local_port,
                    remote_address: None,
                    remote_port: None,
                    state: "Listening".to_string(),
                    pid,
                });
            }
        }
    }

    Ok(snapshots)
}

fn build_pattern_key(socket: &SocketSnapshot, process: &crate::models::ProcessIdentity) -> String {
    let fingerprint = process
        .exe_path
        .clone()
        .or_else(|| process.sha256.clone())
        .unwrap_or_else(|| process.name.to_ascii_lowercase());
    let service_port = socket_service_port(socket);
    let remote_scope = baseline_remote_dimension(socket);
    format!(
        "{fingerprint}|{}|{}|{service_port}|{remote_scope}",
        socket.protocol.to_ascii_lowercase(),
        socket.direction.to_ascii_lowercase()
    )
}

fn build_alert_key(socket: &SocketSnapshot, process: &crate::models::ProcessIdentity) -> String {
    let fingerprint = process
        .exe_path
        .clone()
        .or_else(|| process.sha256.clone())
        .unwrap_or_else(|| process.name.to_ascii_lowercase());
    let service_port = socket_service_port(socket);
    format!(
        "{fingerprint}|{}|{}|{}|{}|{service_port}",
        socket.protocol.to_ascii_lowercase(),
        socket.direction.to_ascii_lowercase(),
        local_binding_dimension(&socket.local_address),
        alert_remote_dimension(socket)
    )
}

fn build_pattern_summary(socket: &SocketSnapshot, process: &crate::models::ProcessIdentity) -> String {
    let service_port = socket_service_port(socket);
    format!(
        "{} / {} / {} / {} / {}",
        process.name,
        socket.protocol,
        socket.direction,
        classify_remote_scope(socket.remote_address.as_deref()),
        service_port
    )
}

fn socket_service_port(socket: &SocketSnapshot) -> u16 {
    match socket.direction.as_str() {
        "incoming" | "listening" => socket.local_port,
        _ => socket.remote_port.unwrap_or(socket.local_port),
    }
}

fn classify_remote_scope(remote: Option<&str>) -> &'static str {
    let Some(remote) = remote else {
        return "listener";
    };

    if remote.eq_ignore_ascii_case("localhost") {
        return "loopback";
    }

    match remote.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_loopback() => "loopback",
        Ok(IpAddr::V4(ip)) if ip.is_private() || ip.is_link_local() => "private",
        Ok(IpAddr::V6(ip)) if ip.is_loopback() => "loopback",
        Ok(IpAddr::V6(ip)) if ip.is_unique_local() || ip.is_unicast_link_local() => "private",
        Ok(_) => "public",
        Err(_) => "public",
    }
}

fn baseline_remote_dimension(socket: &SocketSnapshot) -> String {
    let Some(remote) = socket.remote_address.as_deref() else {
        return format!("listener:{}", local_binding_dimension(&socket.local_address));
    };

    if is_common_web_or_dns_port(socket.remote_port.unwrap_or_default()) {
        return format!(
            "{}:{}",
            classify_remote_scope(Some(remote)),
            socket.remote_port.unwrap_or_default()
        );
    }

    match classify_remote_scope(Some(remote)) {
        "private" | "loopback" => remote.to_ascii_lowercase(),
        _ => format!("public:{remote}"),
    }
}

fn alert_remote_dimension(socket: &SocketSnapshot) -> String {
    match socket.remote_address.as_deref() {
        Some(remote) => remote.to_ascii_lowercase(),
        None => format!("listener:{}", socket.local_address.to_ascii_lowercase()),
    }
}

fn local_binding_dimension(local_address: &str) -> &'static str {
    if matches!(local_address, "0.0.0.0" | "::") {
        return "unspecified";
    }
    if let Ok(IpAddr::V4(ip)) = local_address.parse::<IpAddr>() {
        if ip.is_loopback() {
            return "loopback";
        }
        if ip.is_private() || ip.is_link_local() {
            return "private";
        }
        return "public";
    }
    if let Ok(IpAddr::V6(ip)) = local_address.parse::<IpAddr>() {
        if ip.is_loopback() {
            return "loopback";
        }
        if ip.is_unique_local() || ip.is_unicast_link_local() {
            return "private";
        }
        return "public";
    }
    "other"
}

fn is_common_web_or_dns_port(port: u16) -> bool {
    matches!(port, 53 | 80 | 123 | 443)
}

fn build_activity_event(
    connection: &ConnectionEvent,
    change_type: &str,
    timestamp: chrono::DateTime<Utc>,
) -> ActivityEvent {
    let mut snapshot = connection.clone();
    snapshot.timestamp = timestamp;
    snapshot.is_new = change_type == "opened";

    ActivityEvent {
        id: Uuid::new_v4().to_string(),
        timestamp,
        change_type: change_type.to_string(),
        connection: snapshot,
    }
}

fn build_alert_timeline_event(
    alert: &AlertRecord,
    previous: Option<&AlertRecord>,
    timestamp: chrono::DateTime<Utc>,
) -> crate::models::AlertTimelineEvent {
    let event_type = match previous {
        None => "created",
        Some(existing)
            if existing.risk_level != alert.risk_level
                && matches!(
                    (&existing.risk_level, &alert.risk_level),
                    (RiskLevel::Unknown, RiskLevel::Suspicious)
                ) =>
        {
            "escalated"
        }
        Some(_) => "updated",
    };

    let summary = match event_type {
        "created" => format!(
            "Alert created with score {} and {} occurrence.",
            alert.score, alert.occurrence_count
        ),
        "escalated" => format!(
            "Alert escalated to {:?} with score {} after {} occurrence(s).",
            alert.risk_level, alert.score, alert.occurrence_count
        ),
        _ => format!(
            "Alert updated to score {} with {} occurrence(s).",
            alert.score, alert.occurrence_count
        ),
    };

    crate::models::AlertTimelineEvent {
        id: Uuid::new_v4().to_string(),
        alert_id: alert.id.clone(),
        timestamp,
        event_type: event_type.to_string(),
        status: alert.status.clone(),
        risk_level: alert.risk_level.clone(),
        score: alert.score,
        confidence: alert.confidence,
        occurrence_count: alert.occurrence_count,
        summary,
    }
}

fn make_snapshot_id(
    protocol: &str,
    pid: u32,
    local_address: &str,
    local_port: u16,
    remote_address: Option<&str>,
    remote_port: Option<u16>,
) -> String {
    format!(
        "{protocol}:{pid}:{local_address}:{local_port}:{}:{}",
        remote_address.unwrap_or("*"),
        remote_port.unwrap_or_default()
    )
}

fn infer_tcp_direction(state: TcpState, local_port: u16, remote_port: u16) -> String {
    if state == TcpState::Listen {
        return "listening".to_string();
    }
    if state == TcpState::TimeWait {
        return "closed".to_string();
    }
    if state == TcpState::CloseWait {
        return "closing".to_string();
    }
    if local_port >= 49_152 && remote_port > 0 && remote_port < 49_152 {
        return "outgoing".to_string();
    }
    if remote_port >= 49_152 && local_port > 0 && local_port < 49_152 {
        return "incoming".to_string();
    }
    if remote_port != 0 && remote_port <= 1024 && local_port > 1024 {
        return "outgoing".to_string();
    }
    if local_port != 0 && local_port <= 1024 && remote_port > 1024 {
        return "incoming".to_string();
    }
    "outgoing".to_string()
}

#[cfg(test)]
mod tests {
    use super::{build_alert_key, build_pattern_key, infer_tcp_direction, make_snapshot_id};
    use crate::models::ProcessIdentity;
    use netstat2::TcpState;

    #[test]
    fn listener_direction_is_reported() {
        assert_eq!(infer_tcp_direction(TcpState::Listen, 3389, 0), "listening");
    }

    #[test]
    fn snapshot_id_is_stable() {
        let id = make_snapshot_id("tcp", 7, "127.0.0.1", 8080, Some("1.1.1.1"), Some(443));
        assert_eq!(id, "tcp:7:127.0.0.1:8080:1.1.1.1:443");
    }

    #[test]
    fn pattern_key_ignores_ephemeral_local_port() {
        let process = ProcessIdentity {
            pid: 1,
            name: "chrome.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Chrome\\chrome.exe".to_string()),
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: None,
            is_signed: true,
            publisher: None,
            sha256: Some("abc".to_string()),
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };
        let left = build_pattern_key(
            &crate::models::SocketSnapshot {
                id: "1".to_string(),
                protocol: "tcp".to_string(),
                direction: "outgoing".to_string(),
                local_address: "127.0.0.1".to_string(),
                local_port: 50_000,
                remote_address: Some("8.8.8.8".to_string()),
                remote_port: Some(443),
                state: "Established".to_string(),
                pid: 1,
            },
            &process,
        );
        let right = build_pattern_key(
            &crate::models::SocketSnapshot {
                local_port: 50_100,
                ..crate::models::SocketSnapshot {
                    id: "1".to_string(),
                    protocol: "tcp".to_string(),
                    direction: "outgoing".to_string(),
                    local_address: "127.0.0.1".to_string(),
                    local_port: 50_000,
                    remote_address: Some("8.8.8.8".to_string()),
                    remote_port: Some(443),
                    state: "Established".to_string(),
                    pid: 1,
                }
            },
            &process,
        );
        assert_eq!(left, right);
    }

    #[test]
    fn alert_key_distinguishes_public_destinations() {
        let process = ProcessIdentity {
            pid: 1,
            name: "chrome.exe".to_string(),
            exe_path: Some("C:\\Program Files\\Chrome\\chrome.exe".to_string()),
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: None,
            is_signed: true,
            publisher: None,
            sha256: Some("abc".to_string()),
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };
        let left = build_alert_key(
            &crate::models::SocketSnapshot {
                id: "1".to_string(),
                protocol: "tcp".to_string(),
                direction: "outgoing".to_string(),
                local_address: "127.0.0.1".to_string(),
                local_port: 50_000,
                remote_address: Some("1.1.1.1".to_string()),
                remote_port: Some(443),
                state: "Established".to_string(),
                pid: 1,
            },
            &process,
        );
        let right = build_alert_key(
            &crate::models::SocketSnapshot {
                id: "2".to_string(),
                protocol: "tcp".to_string(),
                direction: "outgoing".to_string(),
                local_address: "127.0.0.1".to_string(),
                local_port: 50_001,
                remote_address: Some("8.8.8.8".to_string()),
                remote_port: Some(443),
                state: "Established".to_string(),
                pid: 1,
            },
            &process,
        );
        assert_ne!(left, right);
    }
}
