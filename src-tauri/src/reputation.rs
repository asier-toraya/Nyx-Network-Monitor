use chrono::{Duration, Utc};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::{
    db::Database,
    models::{AppSettings, ReputationInfo},
};

pub fn resolve_reputation(
    database: &Database,
    settings: &AppSettings,
    remote_ip: Option<&str>,
) -> Option<ReputationInfo> {
    let remote_ip = remote_ip?;
    if !settings.enable_reputation || settings.reputation_api_key.as_deref().is_none() {
        return None;
    }

    if is_local_ip(remote_ip) {
        return None;
    }

    if let Ok(Some(cached)) = database.get_cached_reputation(remote_ip) {
        return Some(cached);
    }

    let api_key = settings.reputation_api_key.as_deref()?;
    let client = Client::builder().user_agent("sentinel-desk/0.1.0").build().ok()?;
    let response = client
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", remote_ip), ("maxAgeInDays", "30")])
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send()
        .ok()?;

    let payload = response.json::<AbuseIpDbResponse>().ok()?;
    let verdict = if payload.data.abuse_confidence_score >= 75 {
        "malicious"
    } else if payload.data.abuse_confidence_score == 0 {
        "trusted"
    } else {
        "unknown"
    };

    let record = ReputationInfo {
        source: "abuseipdb".to_string(),
        verdict: verdict.to_string(),
        score: Some(payload.data.abuse_confidence_score),
        summary: format!(
            "Abuse confidence score {} with {} total reports.",
            payload.data.abuse_confidence_score, payload.data.total_reports
        ),
        checked_at: Utc::now(),
    };

    let expires_at = Utc::now() + Duration::minutes(settings.reputation_ttl_minutes as i64);
    let _ = database.set_cached_reputation(remote_ip, &record, expires_at);

    Some(record)
}

fn is_local_ip(value: &str) -> bool {
    value.starts_with("127.")
        || value.starts_with("10.")
        || value.starts_with("192.168.")
        || value.starts_with("172.16.")
        || value == "::1"
        || value.starts_with("fe80:")
        || value.starts_with("fd")
}

#[derive(Debug, Deserialize)]
struct AbuseIpDbResponse {
    data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIpDbData {
    abuse_confidence_score: i32,
    total_reports: i32,
}

