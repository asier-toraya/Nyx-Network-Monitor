use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::{
    db::Database,
    models::{AppSettings, DestinationInfo},
};

pub fn resolve_destination(
    database: &Database,
    settings: &AppSettings,
    remote_ip: Option<&str>,
) -> Option<DestinationInfo> {
    let remote_ip = remote_ip?;
    let scope = classify_scope(remote_ip)?;

    if scope != "public" {
        return Some(local_destination_info(remote_ip, scope));
    }

    if !settings.enable_destination_enrichment {
        return Some(DestinationInfo {
            ip: remote_ip.to_string(),
            scope: scope.to_string(),
            hostname: None,
            domain: None,
            asn: None,
            organization: None,
            country: None,
            source: "scope only".to_string(),
            checked_at: Utc::now(),
        });
    }

    if let Ok(Some(cached)) = database.get_cached_destination(remote_ip) {
        return Some(cached);
    }

    let hostname = resolve_reverse_dns(remote_ip);
    let whois = fetch_ipwhois(remote_ip);

    let record = DestinationInfo {
        ip: remote_ip.to_string(),
        scope: scope.to_string(),
        hostname,
        domain: whois.as_ref().and_then(|payload| payload.connection.domain.clone()),
        asn: whois
            .as_ref()
            .and_then(|payload| payload.connection.asn.map(|asn| format!("AS{asn}"))),
        organization: whois.as_ref().and_then(|payload| payload.connection.org.clone()),
        country: whois.as_ref().and_then(|payload| payload.country.clone()),
        source: settings.destination_provider.clone(),
        checked_at: Utc::now(),
    };

    let expires_at = Utc::now() + ChronoDuration::minutes(settings.destination_ttl_minutes as i64);
    let _ = database.set_cached_destination(remote_ip, &record, expires_at);

    Some(record)
}

fn local_destination_info(ip: &str, scope: &str) -> DestinationInfo {
    let organization = match scope {
        "loopback" => Some("Local host".to_string()),
        "private" => Some("Private network".to_string()),
        "link_local" => Some("Link-local network".to_string()),
        _ => None,
    };

    DestinationInfo {
        ip: ip.to_string(),
        scope: scope.to_string(),
        hostname: None,
        domain: None,
        asn: None,
        organization,
        country: None,
        source: "local scope".to_string(),
        checked_at: Utc::now(),
    }
}

fn classify_scope(value: &str) -> Option<&'static str> {
    let ip = value.parse::<IpAddr>().ok()?;

    let scope = match ip {
        IpAddr::V4(ip) if ip.is_loopback() => "loopback",
        IpAddr::V4(ip) if ip.is_link_local() => "link_local",
        IpAddr::V4(ip) if ip.is_private() => "private",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) => "unspecified",
        IpAddr::V6(ip) if ip.is_loopback() => "loopback",
        IpAddr::V6(ip) if ip.is_unicast_link_local() => "link_local",
        IpAddr::V6(ip) if ip.is_unique_local() => "private",
        IpAddr::V6(ip) if ip == Ipv6Addr::UNSPECIFIED => "unspecified",
        _ => "public",
    };

    Some(scope)
}

fn resolve_reverse_dns(ip: &str) -> Option<String> {
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         $entry = Resolve-DnsName -Name '{ip}' -Type PTR | Select-Object -First 1 -ExpandProperty NameHost; \
         if ($entry) {{ $entry.TrimEnd('.') }}"
    );

    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn fetch_ipwhois(ip: &str) -> Option<IpWhoisResponse> {
    let client = Client::builder()
        .user_agent("sentinel-desk/0.1.0")
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;

    let response = client
        .get(format!("https://ipwho.is/{ip}"))
        .send()
        .ok()?;

    let payload = response.json::<IpWhoisResponse>().ok()?;
    payload.success.then_some(payload)
}

#[derive(Debug, Deserialize)]
struct IpWhoisResponse {
    success: bool,
    country: Option<String>,
    connection: IpWhoisConnection,
}

#[derive(Debug, Deserialize, Default)]
struct IpWhoisConnection {
    asn: Option<u32>,
    org: Option<String>,
    domain: Option<String>,
}

