use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::models::{
    AllowRule, AppSettings, ClassificationResult, ProcessIdentity, ReputationInfo, RiskLevel,
    RiskReason, SocketSnapshot, TrafficBaseline,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketStateProfile {
    Listening,
    TimeWait,
    CloseWait,
    Established,
    SynSent,
    Active,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathContext {
    System,
    Installed,
    UserWritable,
    Other,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessRole {
    CoreWindows,
    ServiceHost,
    Browser,
    Collaboration,
    GamingOrVpn,
    UpdateService,
    ScriptHost,
    Office,
    Pdf,
    UserShell,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserContext {
    System,
    LocalService,
    NetworkService,
    ServiceSid,
    InteractiveUser,
}

pub fn classify_connection(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    reputation: Option<&ReputationInfo>,
    baseline: Option<&TrafficBaseline>,
    allow_rules: &[AllowRule],
    settings: &AppSettings,
) -> ClassificationResult {
    if let Some(reason) = match_allow_rule(socket, process, allow_rules) {
        return ClassificationResult {
            risk_level: RiskLevel::Safe,
            score: 0,
            confidence: 96,
            reasons: vec![reason],
            recommended_action: "Connection is explicitly trusted by an allow rule.".to_string(),
            suggested_firewall_rule: None,
        };
    }

    let process_name = process.name.to_ascii_lowercase();
    let state_profile = socket_state_profile(socket);
    let path_context = classify_path(process.exe_path.as_deref());
    let role = process_role(&process_name);
    let service_port = effective_service_port(socket);
    let destination = socket.remote_address.as_deref();
    let is_listener = matches!(state_profile, SocketStateProfile::Listening);
    let is_active_connection = matches!(
        state_profile,
        SocketStateProfile::Established | SocketStateProfile::SynSent | SocketStateProfile::Active
    );
    let is_public_remote = destination.is_some_and(|value| !is_local_or_private(value));
    let is_sensitive_service = service_port
        .map(|port| settings.suspicious_ports.contains(&port))
        .unwrap_or(false);
    let expected_parent = has_expected_parent_context(process);
    let expected_user = has_expected_user_context(process);
    let metadata_grace =
        should_grace_metadata(process, socket, path_context, expected_parent, expected_user);

    if let Some(port) = service_port.filter(|port| is_known_windows_listener(socket, process, *port))
    {
        return ClassificationResult {
            risk_level: RiskLevel::Safe,
            score: 0,
            confidence: 94,
            reasons: build_known_windows_listener_reasons(socket, process, port),
            recommended_action: build_known_windows_listener_explanation(socket, process, port),
            suggested_firewall_rule: None,
        };
    }

    if let Some(port) = service_port.filter(|port| {
        is_legitimate_dynamic_rpc_listener(socket, process, *port, path_context)
    }) {
        return ClassificationResult {
            risk_level: RiskLevel::Safe,
            score: 0,
            confidence: 92,
            reasons: build_dynamic_rpc_listener_reasons(process, port),
            recommended_action: build_dynamic_rpc_listener_explanation(process, port),
            suggested_firewall_rule: None,
        };
    }

    if matches!(state_profile, SocketStateProfile::TimeWait) {
        return build_time_wait_result(socket, process, service_port);
    }

    let mut score = 0;
    let mut confidence = 40;
    let mut reasons = Vec::new();

    match state_profile {
        SocketStateProfile::Listening => {
            score -= 8;
            reasons.push(reason(
                "listening_socket_no_peer",
                "Listening socket, no remote peer is attached.",
            ));

            if is_local_or_unspecified_binding(&socket.local_address) {
                score -= 4;
                reasons.push(reason(
                    "local_listener_binding",
                    "Listener is bound to a local or unspecified interface, which is common for service registration.",
                ));
            }
        }
        SocketStateProfile::CloseWait => {
            score -= 4;
            confidence -= 2;
            reasons.push(reason(
                "stale_tcp_close_wait",
                "Socket is in CLOSE_WAIT, which is usually a stale or technical shutdown state rather than active beaconing.",
            ));
        }
        SocketStateProfile::Established => {
            score += 3;
            reasons.push(reason(
                "active_established_connection",
                "Established connection is active and should be scored with full context.",
            ));
        }
        SocketStateProfile::SynSent => {
            score += 5;
            confidence -= 2;
            reasons.push(reason(
                "outbound_connection_attempt",
                "Outbound connection attempt is in progress and worth monitoring in context.",
            ));
        }
        SocketStateProfile::Active => {
            score += 2;
            reasons.push(reason(
                "active_connection_state",
                "TCP state indicates the socket is active rather than passive.",
            ));
        }
        SocketStateProfile::Other | SocketStateProfile::TimeWait => {}
    }

    match path_context {
        PathContext::System => {
            score -= 6;
            confidence += 8;
            reasons.push(reason(
                "expected_system_path",
                "Executable path matches a standard Windows system location.",
            ));
        }
        PathContext::Installed => {
            confidence += 6;
            reasons.push(reason(
                "expected_install_path",
                "Executable path matches a common installed application location.",
            ));
        }
        PathContext::UserWritable => {
            score += 18;
            confidence += 4;
            reasons.push(reason(
                "user_writable_execution_path",
                "Executable is running from a user-writable location such as AppData, Temp, Downloads or Public.",
            ));
        }
        PathContext::Other => {}
        PathContext::Missing => {
            if metadata_grace {
                confidence -= 2;
                reasons.push(reason(
                    "metadata_gap_expected_context",
                    "Missing executable path is tolerated here because the process context matches expected Windows behavior.",
                ));
            } else {
                score += 4;
                confidence -= 10;
                reasons.push(reason(
                    "missing_path",
                    "The executable path could not be resolved for the owning PID.",
                ));
            }
        }
    }

    if high_trust_windows_processes().contains(process_name.as_str()) {
        if matches!(path_context, PathContext::UserWritable) {
            score += 30;
            reasons.push(reason(
                "core_process_name_in_suspicious_path",
                "A high-trust Windows process name is running from a user-writable path, which is not expected.",
            ));
        } else if expected_parent != Some(false) && expected_user != Some(false) {
            score -= 10;
            confidence += 10;
            reasons.push(reason(
                "trusted_windows_process_baseline",
                "Process identity matches a common Windows baseline and is running in an expected context.",
            ));
        }
    }

    if process.metadata_pending {
        confidence -= 4;
        reasons.push(reason(
            "identity_pending",
            "Digital signature and file hash are still being resolved in the background.",
        ));
    } else if process.is_signed {
        score -= 14;
        confidence += 12;
        reasons.push(reason(
            "signed_process",
            "Executable is digitally signed and publisher metadata was resolved.",
        ));
    } else if metadata_grace {
        confidence -= 2;
        reasons.push(reason(
            "protected_process_metadata_limited",
            "Missing signer metadata is not treated as suspicious here because protected Windows processes often expose limited metadata.",
        ));
    } else {
        score += 18;
        confidence -= 10;
        reasons.push(reason(
            "unsigned_process",
            "Executable is not signed or the signature could not be validated.",
        ));
    }

    if process.metadata_pending {
        confidence -= 2;
    } else if process.sha256.is_some() {
        confidence += 10;
        reasons.push(reason(
            "hashed_binary",
            "A stable file hash was captured for the executable, which improves attribution quality.",
        ));
    } else if !metadata_grace {
        confidence -= 6;
    }

    if let Some(matches_parent) = expected_parent {
        if matches_parent {
            score -= 6;
            confidence += 4;
            reasons.push(reason(
                "expected_parent_process",
                "Parent-child process relationship matches a normal Windows baseline.",
            ));
        } else {
            score += 14;
            reasons.push(reason(
                "unexpected_parent_process",
                "Parent-child process relationship does not match the expected Windows baseline.",
            ));
        }
    }

    if let Some(matches_user) = expected_user {
        if matches_user {
            score -= 6;
            confidence += 4;
            reasons.push(reason(
                "expected_user_context",
                "Process is running under an expected Windows service or interactive account context.",
            ));
        } else {
            score += 16;
            reasons.push(reason(
                "unexpected_user_context",
                "Process is running under an unexpected account context for its role.",
            ));
        }
    }

    if matches!(role, ProcessRole::ServiceHost) {
        if let Some(service_reason) = trusted_svchost_reason(process) {
            score -= 10;
            confidence += 6;
            reasons.push(service_reason);
        } else if process.service_context_pending {
            confidence -= 4;
            reasons.push(reason(
                "svchost_service_context_pending",
                "Hosted Windows services are still being resolved for this svchost instance.",
            ));
        } else {
            confidence -= 4;
            reasons.push(reason(
                "svchost_service_context_unavailable",
                "Hosted Windows services could not be resolved. Treat this as incomplete context rather than proof of malicious activity.",
            ));
        }
    }

    if destination.is_some_and(is_local_or_private) {
        score -= 8;
        reasons.push(reason(
            "private_destination",
            "Remote endpoint stays inside loopback, link-local or private address ranges.",
        ));
    } else if is_public_remote && is_active_connection {
        score += 4;
        reasons.push(reason(
            "public_destination",
            "Connection reaches a public address that should be reviewed in context.",
        ));
    }

    if let Some(port) = service_port {
        if common_safe_remote_ports().contains(&port) && is_active_connection {
            match role {
                ProcessRole::Browser
                | ProcessRole::Collaboration
                | ProcessRole::GamingOrVpn
                | ProcessRole::UpdateService => {
                    score -= 10;
                    reasons.push(reason(
                        "role_expected_web_traffic",
                        "This process role commonly maintains HTTPS, DNS or NTP sessions as part of normal activity.",
                    ));
                }
                _ => {
                    score -= 4;
                    reasons.push(reason(
                        "expected_service_port",
                        "Traffic uses a common service port such as HTTPS or DNS.",
                    ));
                }
            }
        }

        if is_dynamic_rpc_port(port)
            && is_listener
            && high_trust_windows_processes().contains(process_name.as_str())
            && path_context != PathContext::UserWritable
        {
            score -= 4;
            reasons.push(reason(
                "dynamic_rpc_or_service_port",
                "High dynamic port matches common Windows RPC or service communication behavior.",
            ));
        }

        if matches!(role, ProcessRole::CoreWindows) && is_public_remote && is_active_connection {
            score += 12;
            reasons.push(reason(
                "core_process_external_public_traffic",
                "Core Windows process is communicating with a public external address, which deserves extra scrutiny.",
            ));
        }

        if matches!(role, ProcessRole::ScriptHost) && is_public_remote && is_active_connection {
            score += 16;
            reasons.push(reason(
                "script_host_external_traffic",
                "Script host or LOLBin is making an external network connection.",
            ));
        }

        if matches!(role, ProcessRole::Office | ProcessRole::Pdf)
            && is_public_remote
            && is_active_connection
        {
            score += 10;
            reasons.push(reason(
                "document_app_external_traffic",
                "Office or document viewer process is making an external network connection and should be reviewed in context.",
            ));
        }

        if settings.suspicious_ports.contains(&port) {
            let contextual_ok = is_contextually_expected(socket, process, port);
            if contextual_ok {
                score -= 4;
                reasons.push(reason(
                    "sensitive_port_expected",
                    "Sensitive port usage matches a common administrative tool or local workflow.",
                ));
            } else if is_listener {
                score += 14;
                reasons.push(reason(
                    "sensitive_listener_unexpected",
                    "Sensitive service port is exposed by a listener outside the expected Windows or admin context.",
                ));
            } else if matches!(state_profile, SocketStateProfile::CloseWait) {
                score += 4;
                reasons.push(reason(
                    "sensitive_port_during_close",
                    "Sensitive port was observed while the connection was closing; review it in broader context.",
                ));
            } else {
                score += 22;
                reasons.push(reason(
                    "sensitive_port_unexpected",
                    "Sensitive service port is in use outside the expected context.",
                ));
            }
        }
    }

    if is_listener
        && settings.suspicious_ports.contains(&socket.local_port)
        && !is_known_windows_listener(socket, process, socket.local_port)
    {
        score += 8;
        reasons.push(reason(
            "new_listener",
            "A listener is bound to a sensitive local port and should be reviewed in context.",
        ));
    }

    let baseline_hits = baseline.map(|entry| entry.hit_count).unwrap_or(0);
    if baseline_hits == 0 {
        if is_active_connection || (is_listener && !high_trust_windows_processes().contains(process_name.as_str())) {
            score += 4;
            reasons.push(reason(
                "first_seen_pattern",
                "This process and service-port pattern has not been observed before on this device.",
            ));
        }
    } else if baseline_hits < settings.baseline_learning_threshold {
        confidence += 4;
        reasons.push(reason(
            "learning_pattern",
            &format!(
                "This pattern has been seen {} time(s); it is still in the local learning period.",
                baseline_hits
            ),
        ));
    } else if is_sensitive_service {
        score -= 3;
        confidence += 8;
        reasons.push(reason(
            "baseline_seen_sensitive",
            &format!(
                "This sensitive pattern has been seen {} times before, so it is no longer treated as brand new.",
                baseline_hits
            ),
        ));
    } else {
        score -= 12;
        confidence += 12;
        reasons.push(reason(
            "baseline_established",
            &format!(
                "This process and service-port pattern has been seen {} times before on this device.",
                baseline_hits
            ),
        ));
    }

    if let Some(reputation) = reputation {
        if is_active_connection && is_public_remote {
            confidence += 10;
            match reputation.verdict.as_str() {
                "malicious" | "abusive" => {
                    score += 35;
                    reasons.push(reason(
                        "bad_reputation",
                        "External reputation lookup marked the remote IP as abusive.",
                    ));
                }
                "trusted" | "clean" => {
                    score -= 12;
                    reasons.push(reason(
                        "good_reputation",
                        "External reputation lookup found no meaningful abuse signals.",
                    ));
                }
                _ => {
                    score += 5;
                    reasons.push(reason(
                        "unknown_reputation",
                        "The remote IP did not have enough reputation data for a clear verdict.",
                    ));
                }
            }
        }
    } else if is_active_connection && socket.remote_address.is_some() {
        reasons.push(reason(
            "reputation_skipped",
            "No external reputation data was available, so scoring stayed local only.",
        ));
    }

    if (process.pid == 0 || process.name.eq_ignore_ascii_case("unknown"))
        && !matches!(state_profile, SocketStateProfile::CloseWait)
    {
        if is_active_connection {
            score += 8;
            confidence -= 15;
            reasons.push(reason(
                "weak_process_attribution",
                "Owning process attribution is incomplete, so the verdict should be read with caution.",
            ));
        } else {
            score += 2;
            confidence -= 8;
            reasons.push(reason(
                "weak_process_attribution",
                "Owning process attribution is incomplete, but the socket is not currently active.",
            ));
        }
    }

    let mut risk_level = if score <= 4 {
        RiskLevel::Safe
    } else if score < 38 {
        RiskLevel::Unknown
    } else {
        RiskLevel::Suspicious
    };

    if should_cap_at_unknown(socket, process, path_context, &reasons)
        && matches!(risk_level, RiskLevel::Suspicious)
    {
        risk_level = RiskLevel::Unknown;
    }

    let confidence = confidence.clamp(20, 98);
    let recommended_action =
        recommended_action_for(risk_level.clone(), state_profile, process, service_port, &reasons);
    let suggested_firewall_rule = if matches!(state_profile, SocketStateProfile::CloseWait) {
        None
    } else {
        build_firewall_suggestion(socket)
    };

    ClassificationResult {
        risk_level,
        score: score.max(0),
        confidence,
        reasons,
        recommended_action,
        suggested_firewall_rule,
    }
}

fn reason(code: &str, message: &str) -> RiskReason {
    RiskReason {
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn common_safe_remote_ports() -> HashSet<u16> {
    [53, 80, 123, 443].into_iter().collect()
}

fn high_trust_windows_processes() -> HashSet<&'static str> {
    [
        "system",
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "spoolsv.exe",
        "explorer.exe",
        "dwm.exe",
    ]
    .into_iter()
    .collect()
}

fn core_windows_dynamic_rpc_processes() -> HashSet<&'static str> {
    [
        "system",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "spoolsv.exe",
        "dwm.exe",
    ]
    .into_iter()
    .collect()
}

fn trusted_svchost_services() -> HashSet<&'static str> {
    [
        "rpcss",
        "rpceptmapper",
        "dnscache",
        "windefend",
        "eventlog",
        "schedule",
        "lanmanserver",
        "lanmanworkstation",
    ]
    .into_iter()
    .collect()
}

fn match_allow_rule(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    allow_rules: &[AllowRule],
) -> Option<RiskReason> {
    allow_rules.iter().find_map(|rule| {
        if !rule.enabled {
            return None;
        }

        let process_match = rule
            .process_name
            .as_deref()
            .map(|expected| expected.eq_ignore_ascii_case(&process.name))
            .unwrap_or(true);
        let signer_match = rule
            .signer
            .as_deref()
            .map(|expected| process.signer.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(expected)))
            .unwrap_or(true);
        let path_match = rule
            .exe_path
            .as_deref()
            .map(|expected| process.exe_path.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(expected)))
            .unwrap_or(true);
        let hash_match = rule
            .sha256
            .as_deref()
            .map(|expected| process.sha256.as_deref().is_some_and(|value| value.eq_ignore_ascii_case(expected)))
            .unwrap_or(true);
        let remote_match = rule
            .remote_pattern
            .as_deref()
            .map(|expected| {
                socket
                    .remote_address
                    .as_deref()
                    .is_some_and(|value| remote_pattern_matches(expected, value))
            })
            .unwrap_or(true);
        let port_match = rule
            .port
            .map(|expected| socket.remote_port == Some(expected) || socket.local_port == expected)
            .unwrap_or(true);
        let protocol_match = rule
            .protocol
            .as_deref()
            .map(|expected| expected.eq_ignore_ascii_case(&socket.protocol))
            .unwrap_or(true);
        let direction_match = rule
            .direction
            .as_deref()
            .map(|expected| expected.eq_ignore_ascii_case(&socket.direction))
            .unwrap_or(true);

        if process_match
            && signer_match
            && path_match
            && hash_match
            && remote_match
            && port_match
            && protocol_match
            && direction_match
        {
            Some(reason(
                "allowlisted",
                &format!("Matched strict allow rule '{}'.", rule.label),
            ))
        } else {
            None
        }
    })
}

fn remote_pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let normalized_pattern = pattern.to_ascii_lowercase();
    let normalized_value = value.to_ascii_lowercase();

    if normalized_pattern.starts_with("*.") {
        return normalized_value.ends_with(&normalized_pattern[1..]);
    }

    if normalized_pattern.ends_with('*') {
        let prefix = normalized_pattern.trim_end_matches('*');
        return normalized_value.starts_with(prefix);
    }

    normalized_value == normalized_pattern
}

fn effective_service_port(socket: &SocketSnapshot) -> Option<u16> {
    match socket.direction.as_str() {
        "listening" => Some(socket.local_port),
        _ => socket.remote_port.or(Some(socket.local_port)),
    }
}

fn is_contextually_expected(socket: &SocketSnapshot, process: &ProcessIdentity, port: u16) -> bool {
    let name = process.name.to_ascii_lowercase();
    match port {
        22 => socket.direction == "outgoing" && (name == "ssh.exe" || name == "code.exe"),
        3389 => socket.direction == "outgoing" && name == "mstsc.exe",
        445 => socket.remote_address.as_deref().is_some_and(is_local_or_private),
        5985 | 5986 => socket.remote_address.as_deref().is_some_and(is_local_or_private),
        135 => {
            is_listening_socket(socket)
                && (is_kernel_system_process(process) || name == "svchost.exe")
        }
        _ => false,
    }
}

fn build_firewall_suggestion(socket: &SocketSnapshot) -> Option<String> {
    if let Some(remote) = socket.remote_address.as_deref() {
        if !is_local_or_private(remote) {
            return Some(format!(
                "New-NetFirewallRule -DisplayName \"Sentinel Desk Block {remote}\" -Direction Outbound -RemoteAddress {remote} -Action Block"
            ));
        }
    }

    if socket.direction == "listening" {
        return Some(format!(
            "New-NetFirewallRule -DisplayName \"Sentinel Desk Block Port {port}\" -Direction Inbound -Protocol {protocol} -LocalPort {port} -Action Block",
            port = socket.local_port,
            protocol = socket.protocol.to_uppercase()
        ));
    }

    None
}

fn socket_state_profile(socket: &SocketSnapshot) -> SocketStateProfile {
    let normalized = normalize_state(&socket.state);

    if is_listening_socket(socket) || normalized == "listen" || normalized == "listening" {
        return SocketStateProfile::Listening;
    }

    match normalized.as_str() {
        "timewait" => SocketStateProfile::TimeWait,
        "closewait" => SocketStateProfile::CloseWait,
        "established" => SocketStateProfile::Established,
        "synsent" => SocketStateProfile::SynSent,
        "synreceived" | "finwait1" | "finwait2" | "closing" | "lastack" => {
            SocketStateProfile::Active
        }
        _ => SocketStateProfile::Other,
    }
}

fn normalize_state(state: &str) -> String {
    state
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_listening_socket(socket: &SocketSnapshot) -> bool {
    socket.direction.eq_ignore_ascii_case("listening")
        || socket.state.eq_ignore_ascii_case("listen")
        || socket.state.eq_ignore_ascii_case("listening")
}

fn is_kernel_system_process(process: &ProcessIdentity) -> bool {
    process.pid == 4 || process.name.eq_ignore_ascii_case("system")
}

fn is_known_windows_listener(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    port: u16,
) -> bool {
    if !is_listening_socket(socket) || !is_local_or_unspecified_binding(&socket.local_address) {
        return false;
    }

    match port {
        135 => {
            is_kernel_system_process(process) || process.name.eq_ignore_ascii_case("svchost.exe")
        }
        139 | 445 => is_kernel_system_process(process),
        _ => false,
    }
}

fn is_legitimate_dynamic_rpc_listener(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    port: u16,
    path_context: PathContext,
) -> bool {
    if !is_listening_socket(socket)
        || !is_dynamic_rpc_port(port)
        || !is_local_or_unspecified_binding(&socket.local_address)
        || matches!(path_context, PathContext::UserWritable)
    {
        return false;
    }

    let process_name = process.name.to_ascii_lowercase();
    if core_windows_dynamic_rpc_processes().contains(process_name.as_str()) {
        return true;
    }

    process_name == "svchost.exe" && trusted_svchost_service_names(process).next().is_some()
}

fn build_known_windows_listener_reasons(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    port: u16,
) -> Vec<RiskReason> {
    let mut reasons = vec![
        reason(
            "legitimate_windows_listener",
            "Legitimate system listener.",
        ),
        reason(
            "expected_windows_service_port",
            &format!(
                "Expected Windows service port {} for {}.",
                port,
                describe_windows_port(port)
            ),
        ),
        reason(
            "listening_socket_no_peer",
            "Listening socket, no remote peer is attached.",
        ),
    ];

    if is_kernel_system_process(process) {
        reasons.push(reason(
            "kernel_managed_service_binding",
            "Kernel-managed service binding.",
        ));
        reasons.push(reason(
            "system_listener_metadata_expected",
            "Missing executable path or signature metadata is expected for this type of system-owned listener.",
        ));
    } else {
        reasons.push(reason(
            "windows_service_host_listener",
            "Expected Windows service host listener.",
        ));
    }

    if socket.local_address == "0.0.0.0" || socket.local_address == "::" {
        reasons.push(reason(
            "unspecified_windows_binding",
            "Listener is bound to the standard Windows all-interfaces address.",
        ));
    }

    reasons
}

fn build_known_windows_listener_explanation(
    _socket: &SocketSnapshot,
    process: &ProcessIdentity,
    port: u16,
) -> String {
    if is_kernel_system_process(process) {
        return format!(
            "This socket is a standard Windows listening endpoint. PID {} represents the kernel/system networking stack. Port {} is commonly used by {}. Missing executable path is expected for this type of system-owned listener.",
            process.pid,
            port,
            describe_windows_port(port)
        );
    }

    format!(
        "This socket matches an expected Windows service host listener. Port {} is commonly used by {}. A listening socket without a remote peer is normal for this type of service endpoint.",
        port,
        describe_windows_port(port)
    )
}

fn build_dynamic_rpc_listener_reasons(process: &ProcessIdentity, port: u16) -> Vec<RiskReason> {
    let mut reasons = vec![
        reason(
            "legitimate_windows_listener",
            "Legitimate system listener.",
        ),
        reason(
            "windows_system_service_rpc",
            "Windows system service (RPC).",
        ),
        reason(
            "dynamic_rpc_endpoint",
            &format!(
                "Dynamic RPC endpoint is listening on port {} in the standard Windows high-port range.",
                port
            ),
        ),
        reason(
            "listening_socket_no_peer",
            "Listening socket, no remote peer is attached.",
        ),
    ];

    if process.name.eq_ignore_ascii_case("svchost.exe") {
        if let Some(service_reason) = trusted_svchost_reason(process) {
            reasons.push(service_reason);
        }
    } else {
        reasons.push(reason(
            "trusted_windows_process_baseline",
            "Process identity matches a common Windows baseline and is running in an expected listener context.",
        ));
    }

    reasons
}

fn build_dynamic_rpc_listener_explanation(process: &ProcessIdentity, port: u16) -> String {
    if process.name.eq_ignore_ascii_case("svchost.exe") {
        let services = trusted_svchost_service_names(process).collect::<Vec<_>>();
        if !services.is_empty() {
            return format!(
                "This is a Windows service host using a dynamic RPC port. Hosted services such as {} commonly register high-numbered listening ports for internal service communication and do not indicate malicious activity.",
                services.join(", ")
            );
        }
    }

    format!(
        "This is a Windows system process using a dynamic RPC port. High-numbered ports in LISTENING state are commonly used for internal service communication and do not indicate malicious activity. Port {} is within the standard dynamic RPC range.",
        port
    )
}

fn build_time_wait_result(
    _socket: &SocketSnapshot,
    process: &ProcessIdentity,
    service_port: Option<u16>,
) -> ClassificationResult {
    let mut reasons = vec![
        reason(
            "recently_closed_tcp_session",
            "Recently closed TCP session.",
        ),
        reason(
            "tcp_cleanup_state",
            "TIME_WAIT is a TCP cleanup state rather than an active outbound connection.",
        ),
    ];

    if process.pid == 0 || process.name.eq_ignore_ascii_case("unknown") {
        reasons.push(reason(
            "no_active_process_owner_available",
            "No active process owner is available because the original connection owner may already have exited.",
        ));
    }

    if let Some(port) = service_port.filter(|port| common_safe_remote_ports().contains(port)) {
        reasons.push(reason(
            "expected_service_port",
            &format!(
                "Recently closed traffic used common web or infrastructure port {}.",
                port
            ),
        ));
    }

    ClassificationResult {
        risk_level: RiskLevel::Safe,
        score: 0,
        confidence: 86,
        reasons,
        recommended_action: "This entry is in TIME_WAIT state, which usually means the TCP connection has already been closed and is being temporarily retained by the operating system. PID 0 or missing path is expected in some cases because there may no longer be an active owning process.".to_string(),
        suggested_firewall_rule: None,
    }
}

fn describe_windows_port(port: u16) -> &'static str {
    match port {
        53 => "DNS",
        80 => "HTTP",
        135 => "RPC endpoint mapping",
        139 => "NetBIOS session service",
        443 => "HTTPS",
        445 => "SMB",
        _ => "a core Windows service",
    }
}

fn classify_path(path: Option<&str>) -> PathContext {
    let Some(path) = path else {
        return PathContext::Missing;
    };

    let normalized = path.to_ascii_lowercase();

    if normalized.starts_with("c:\\windows\\system32\\")
        || normalized.starts_with("c:\\windows\\syswow64\\")
        || normalized.starts_with("c:\\windows\\winsxs\\")
    {
        return PathContext::System;
    }

    if normalized.starts_with("c:\\program files\\")
        || normalized.starts_with("c:\\program files (x86)\\")
    {
        return PathContext::Installed;
    }

    if normalized.contains("\\appdata\\")
        || normalized.contains("\\temp\\")
        || normalized.contains("\\downloads\\")
        || normalized.contains("\\users\\public\\")
        || normalized.contains("\\desktop\\")
    {
        return PathContext::UserWritable;
    }

    PathContext::Other
}

fn process_role(process_name: &str) -> ProcessRole {
    match process_name {
        "system"
        | "services.exe"
        | "lsass.exe"
        | "wininit.exe"
        | "winlogon.exe"
        | "csrss.exe"
        | "smss.exe"
        | "spoolsv.exe"
        | "dwm.exe" => ProcessRole::CoreWindows,
        "svchost.exe" => ProcessRole::ServiceHost,
        "chrome.exe" | "msedge.exe" | "firefox.exe" | "brave.exe" | "opera.exe" => {
            ProcessRole::Browser
        }
        "discord.exe" | "teams.exe" | "slack.exe" => ProcessRole::Collaboration,
        "steam.exe" | "steamservice.exe" | "openvpn.exe" | "wireguard.exe" | "tailscaled.exe" => {
            ProcessRole::GamingOrVpn
        }
        "onedrive.exe" | "msiexec.exe" | "googleupdate.exe" | "updater.exe" => {
            ProcessRole::UpdateService
        }
        "powershell.exe"
        | "pwsh.exe"
        | "wscript.exe"
        | "cscript.exe"
        | "mshta.exe"
        | "rundll32.exe"
        | "regsvr32.exe"
        | "cmd.exe" => ProcessRole::ScriptHost,
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "onenote.exe" => {
            ProcessRole::Office
        }
        "acrord32.exe" | "acrobat.exe" | "foxitpdfreader.exe" | "sumatrapdf.exe" => {
            ProcessRole::Pdf
        }
        "explorer.exe" => ProcessRole::UserShell,
        _ => ProcessRole::Generic,
    }
}

fn should_grace_metadata(
    process: &ProcessIdentity,
    socket: &SocketSnapshot,
    path_context: PathContext,
    expected_parent: Option<bool>,
    expected_user: Option<bool>,
) -> bool {
    if matches!(socket_state_profile(socket), SocketStateProfile::TimeWait) {
        return true;
    }

    if matches!(path_context, PathContext::UserWritable) {
        return false;
    }

    let process_name = process.name.to_ascii_lowercase();
    let high_trust = high_trust_windows_processes().contains(process_name.as_str());
    if high_trust && expected_parent != Some(false) && expected_user != Some(false) {
        return is_listening_socket(socket) || is_dynamic_rpc_port(socket.local_port);
    }

    process.name.eq_ignore_ascii_case("svchost.exe")
        && is_listening_socket(socket)
        && expected_parent != Some(false)
}

fn has_expected_parent_context(process: &ProcessIdentity) -> Option<bool> {
    let parent_name = process.parent_name.as_deref()?.to_ascii_lowercase();
    let process_name = process.name.to_ascii_lowercase();

    let expected = match process_name.as_str() {
        "svchost.exe" | "spoolsv.exe" => ["services.exe"].as_slice(),
        "services.exe" | "lsass.exe" => ["wininit.exe"].as_slice(),
        "wininit.exe" | "winlogon.exe" | "csrss.exe" => ["smss.exe"].as_slice(),
        "explorer.exe" => ["userinit.exe", "explorer.exe"].as_slice(),
        "dwm.exe" => ["winlogon.exe", "svchost.exe"].as_slice(),
        _ => return None,
    };

    Some(expected.iter().any(|value| parent_name == *value))
}

fn has_expected_user_context(process: &ProcessIdentity) -> Option<bool> {
    let Some(user) = process.user.as_deref() else {
        return None;
    };
    let Some(context) = classify_user_context(user) else {
        return None;
    };
    let process_name = process.name.to_ascii_lowercase();

    let expected = match process_name.as_str() {
        "system"
        | "svchost.exe"
        | "services.exe"
        | "lsass.exe"
        | "wininit.exe"
        | "winlogon.exe"
        | "csrss.exe"
        | "smss.exe"
        | "spoolsv.exe" => matches!(
            context,
            UserContext::System
                | UserContext::LocalService
                | UserContext::NetworkService
                | UserContext::ServiceSid
        ),
        "explorer.exe" | "dwm.exe" => matches!(context, UserContext::InteractiveUser),
        _ => return None,
    };

    Some(expected)
}

fn classify_user_context(value: &str) -> Option<UserContext> {
    let normalized = value.to_ascii_lowercase();

    if normalized.contains("s-1-5-18")
        || normalized == "system"
        || normalized.ends_with("\\system")
    {
        return Some(UserContext::System);
    }

    if normalized.contains("s-1-5-19") || normalized.contains("local service") {
        return Some(UserContext::LocalService);
    }

    if normalized.contains("s-1-5-20") || normalized.contains("network service") {
        return Some(UserContext::NetworkService);
    }

    if normalized.contains("s-1-5-80") {
        return Some(UserContext::ServiceSid);
    }

    if normalized.contains('\\') || normalized.contains('@') || normalized.starts_with("s-1-5-21")
    {
        return Some(UserContext::InteractiveUser);
    }

    None
}

fn trusted_svchost_reason(process: &ProcessIdentity) -> Option<RiskReason> {
    let matched = trusted_svchost_service_names(process).collect::<Vec<_>>();
    if matched.is_empty() {
        return None;
    }

    Some(reason(
        "trusted_svchost_services",
        &format!(
            "svchost.exe is hosting expected Windows services: {}.",
            matched.join(", ")
        ),
    ))
}

fn trusted_svchost_service_names(process: &ProcessIdentity) -> impl Iterator<Item = String> + '_ {
    let trusted = trusted_svchost_services();
    process.hosted_services.iter().filter_map(move |service| {
        trusted
            .contains(service.to_ascii_lowercase().as_str())
            .then(|| service.clone())
    })
}

fn is_dynamic_rpc_port(port: u16) -> bool {
    (49_152..=65_535).contains(&port)
}

fn should_cap_at_unknown(
    socket: &SocketSnapshot,
    process: &ProcessIdentity,
    path_context: PathContext,
    reasons: &[RiskReason],
) -> bool {
    process.name.eq_ignore_ascii_case("svchost.exe")
        && is_listening_socket(socket)
        && is_dynamic_rpc_port(socket.local_port)
        && path_context != PathContext::UserWritable
        && (process.service_context_pending
            || process.hosted_services.is_empty()
            || reasons
                .iter()
                .any(|reason| reason.code == "svchost_service_context_unavailable"))
}

fn recommended_action_for(
    risk_level: RiskLevel,
    state_profile: SocketStateProfile,
    process: &ProcessIdentity,
    service_port: Option<u16>,
    reasons: &[RiskReason],
) -> String {
    if reasons
        .iter()
        .any(|reason| reason.code == "dynamic_rpc_endpoint")
    {
        return build_dynamic_rpc_listener_explanation(process, service_port.unwrap_or_default());
    }

    if reasons
        .iter()
        .any(|reason| reason.code == "recently_closed_tcp_session")
    {
        return "This entry is in TIME_WAIT state, which usually means the TCP connection has already been closed and is being temporarily retained by the operating system. PID 0 or missing path is expected in some cases because there may no longer be an active owning process.".to_string();
    }

    if matches!(state_profile, SocketStateProfile::CloseWait) {
        return "Treat this as a stale or technical socket first. Review the owning process only if the state persists abnormally or other indicators line up.".to_string();
    }

    match risk_level {
        RiskLevel::Safe => {
            "Traffic looks expected for this device baseline. Keep watching for material changes."
                .to_string()
        }
        RiskLevel::Unknown => {
            "Evidence is incomplete or mixed. Review the process path, parent, account context and destination before deciding whether to trust this pattern."
                .to_string()
        }
        RiskLevel::Suspicious => {
            "Multiple risk indicators align here. Inspect the process context immediately and consider containment if the path, parent or destination still look wrong."
                .to_string()
        }
    }
}

fn is_local_or_private(value: &str) -> bool {
    value.parse::<IpAddr>()
        .map(|address| match address {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip == Ipv6Addr::LOCALHOST
            }
        })
        .unwrap_or(false)
        || value == "localhost"
        || value == Ipv4Addr::LOCALHOST.to_string()
}

fn is_local_or_unspecified_binding(value: &str) -> bool {
    value.parse::<IpAddr>()
        .map(|address| match address {
            IpAddr::V4(ip) => {
                ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local()
            }
            IpAddr::V6(ip) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip == Ipv6Addr::LOCALHOST
            }
        })
        .unwrap_or(false)
        || value == "localhost"
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::classify_connection;
    use crate::models::{
        AllowRule, AppSettings, ProcessIdentity, ReputationInfo, RiskLevel, SocketSnapshot,
        TrafficBaseline,
    };

    fn base_process(name: &str, signed: bool) -> ProcessIdentity {
        ProcessIdentity {
            pid: 42,
            name: name.to_string(),
            exe_path: Some(format!("C:\\Program Files\\{name}")),
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: if signed {
                Some("Trusted Publisher".to_string())
            } else {
                None
            },
            is_signed: signed,
            publisher: None,
            sha256: Some("abc123".to_string()),
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        }
    }

    fn base_socket(remote_port: u16, direction: &str) -> SocketSnapshot {
        SocketSnapshot {
            id: "tcp-1".to_string(),
            protocol: "tcp".to_string(),
            direction: direction.to_string(),
            local_address: "192.168.1.20".to_string(),
            local_port: 49823,
            remote_address: Some("8.8.8.8".to_string()),
            remote_port: Some(remote_port),
            state: "Established".to_string(),
            pid: 42,
        }
    }

    fn listener_socket(local_address: &str, local_port: u16, pid: u32) -> SocketSnapshot {
        SocketSnapshot {
            id: "tcp-listener".to_string(),
            protocol: "tcp".to_string(),
            direction: "listening".to_string(),
            local_address: local_address.to_string(),
            local_port,
            remote_address: None,
            remote_port: None,
            state: "Listen".to_string(),
            pid,
        }
    }

    #[test]
    fn signed_browser_to_https_is_safe() {
        let result = classify_connection(
            &base_socket(443, "outgoing"),
            &base_process("chrome.exe", true),
            None,
            Some(&TrafficBaseline {
                pattern_key: "key".to_string(),
                summary: "summary".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                hit_count: 6,
            }),
            &[],
            &AppSettings::default(),
        );
        assert_eq!(result.risk_level, RiskLevel::Safe);
    }

    #[test]
    fn unsigned_sensitive_port_to_public_ip_is_suspicious() {
        let result = classify_connection(
            &base_socket(3389, "outgoing"),
            &base_process("weird.exe", false),
            Some(&ReputationInfo {
                source: "abuseipdb".to_string(),
                verdict: "malicious".to_string(),
                score: Some(90),
                summary: "High abuse confidence".to_string(),
                checked_at: Utc::now(),
            }),
            None,
            &[],
            &AppSettings::default(),
        );
        assert_eq!(result.risk_level, RiskLevel::Suspicious);
    }

    #[test]
    fn unknown_process_with_limited_metadata_is_unknown() {
        let mut process = base_process("oddapp.exe", false);
        process.exe_path = None;
        process.sha256 = None;
        let result = classify_connection(
            &base_socket(8080, "outgoing"),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );
        assert_eq!(result.risk_level, RiskLevel::Unknown);
    }

    #[test]
    fn pending_identity_does_not_trigger_unsigned_penalty() {
        let mut process = base_process("oddapp.exe", false);
        process.sha256 = None;
        process.metadata_pending = true;

        let result = classify_connection(
            &base_socket(443, "outgoing"),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_ne!(result.risk_level, RiskLevel::Suspicious);
        assert!(result.reasons.iter().any(|reason| reason.code == "identity_pending"));
        assert!(result.reasons.iter().all(|reason| reason.code != "unsigned_process"));
    }

    #[test]
    fn allowlisted_ssh_does_not_go_red() {
        let result = classify_connection(
            &base_socket(22, "outgoing"),
            &base_process("ssh.exe", false),
            None,
            None,
            &[AllowRule {
                id: "1".to_string(),
                label: "Trusted admin ssh".to_string(),
                enabled: true,
                process_name: Some("ssh.exe".to_string()),
                signer: None,
                exe_path: Some("C:\\Program Files\\ssh.exe".to_string()),
                sha256: Some("abc123".to_string()),
                remote_pattern: Some("8.8.8.8".to_string()),
                port: Some(22),
                protocol: Some("tcp".to_string()),
                direction: Some("outgoing".to_string()),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            &AppSettings::default(),
        );
        assert_ne!(result.risk_level, RiskLevel::Suspicious);
    }

    #[test]
    fn time_wait_pid0_is_safe() {
        let process = ProcessIdentity {
            pid: 0,
            name: "unknown".to_string(),
            exe_path: None,
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: None,
            is_signed: false,
            publisher: None,
            sha256: None,
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };

        let result = classify_connection(
            &SocketSnapshot {
                id: "timewait".to_string(),
                protocol: "tcp".to_string(),
                direction: "closed".to_string(),
                local_address: "192.168.1.20".to_string(),
                local_port: 49823,
                remote_address: Some("1.1.1.1".to_string()),
                remote_port: Some(443),
                state: "TimeWait".to_string(),
                pid: 0,
            },
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.code == "tcp_cleanup_state"));
        assert!(result
            .reasons
            .iter()
            .all(|reason| reason.code != "unsigned_process" && reason.code != "missing_path"));
    }

    #[test]
    fn pid4_smb_listener_is_legitimate() {
        let process = ProcessIdentity {
            pid: 4,
            name: "System".to_string(),
            exe_path: None,
            user: None,
            parent_pid: None,
            parent_name: None,
            signer: None,
            is_signed: false,
            publisher: None,
            sha256: None,
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };

        let result = classify_connection(
            &listener_socket("0.0.0.0", 445, 4),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert!(result.reasons.iter().any(|reason| reason.code == "legitimate_windows_listener"));
        assert!(result
            .reasons
            .iter()
            .all(|reason| reason.code != "unsigned_process" && reason.code != "missing_path"));
    }

    #[test]
    fn svchost_rpc_listener_is_legitimate() {
        let process = ProcessIdentity {
            pid: 840,
            name: "svchost.exe".to_string(),
            exe_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            user: Some("NT AUTHORITY\\NETWORK SERVICE".to_string()),
            parent_pid: Some(700),
            parent_name: Some("services.exe".to_string()),
            signer: Some("Microsoft Windows".to_string()),
            is_signed: true,
            publisher: Some("Microsoft Windows".to_string()),
            sha256: Some("abc123".to_string()),
            metadata_pending: false,
            hosted_services: vec!["RpcSs".to_string(), "EventLog".to_string()],
            service_context_pending: false,
        };

        let result = classify_connection(
            &listener_socket("::", 49668, 840),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.code == "trusted_svchost_services"));
    }

    #[test]
    fn dynamic_rpc_core_listener_is_legitimate() {
        let process = ProcessIdentity {
            pid: 604,
            name: "lsass.exe".to_string(),
            exe_path: None,
            user: Some("S-1-5-18".to_string()),
            parent_pid: Some(512),
            parent_name: Some("wininit.exe".to_string()),
            signer: None,
            is_signed: false,
            publisher: None,
            sha256: None,
            metadata_pending: false,
            hosted_services: Vec::new(),
            service_context_pending: false,
        };

        let result = classify_connection(
            &listener_socket("0.0.0.0", 49674, 604),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.code == "dynamic_rpc_endpoint"));
    }

    #[test]
    fn core_process_name_from_appdata_is_suspicious() {
        let mut process = base_process("lsass.exe", false);
        process.exe_path = Some("C:\\Users\\Asier\\AppData\\Local\\Temp\\lsass.exe".to_string());
        process.user = Some("Asier-PC\\asier".to_string());
        process.parent_name = Some("explorer.exe".to_string());
        process.sha256 = None;

        let result = classify_connection(
            &base_socket(443, "outgoing"),
            &process,
            None,
            None,
            &[],
            &AppSettings::default(),
        );

        assert_eq!(result.risk_level, RiskLevel::Suspicious);
        assert!(result
            .reasons
            .iter()
            .any(|reason| reason.code == "core_process_name_in_suspicious_path"));
    }

    #[test]
    fn exact_remote_allow_rule_does_not_match_substring() {
        let result = classify_connection(
            &SocketSnapshot {
                remote_address: Some("8.8.8.80".to_string()),
                ..base_socket(22, "outgoing")
            },
            &base_process("ssh.exe", true),
            None,
            None,
            &[AllowRule {
                id: "1".to_string(),
                label: "Exact host".to_string(),
                enabled: true,
                process_name: Some("ssh.exe".to_string()),
                signer: None,
                exe_path: None,
                sha256: None,
                remote_pattern: Some("8.8.8.8".to_string()),
                port: Some(22),
                protocol: Some("tcp".to_string()),
                direction: Some("outgoing".to_string()),
                notes: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }],
            &AppSettings::default(),
        );
        assert!(result.reasons.iter().all(|reason| reason.code != "allowlisted"));
    }

    #[test]
    fn established_baseline_reduces_noise() {
        let result = classify_connection(
            &base_socket(443, "outgoing"),
            &base_process("oddapp.exe", true),
            None,
            Some(&TrafficBaseline {
                pattern_key: "oddapp".to_string(),
                summary: "oddapp / tcp / 443".to_string(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                hit_count: 5,
            }),
            &[],
            &AppSettings::default(),
        );
        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert!(result.confidence >= 60);
    }
}
