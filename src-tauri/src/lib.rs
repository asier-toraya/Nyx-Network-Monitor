mod classifier;
mod command_runner;
mod db;
mod destination;
mod models;
mod monitor;
mod process_info;
mod reputation;

use chrono::Utc;
use monitor::AppState;
use tauri::{Manager, State};
use uuid::Uuid;

use crate::{
    command_runner::{get_established_connections_report, run_connection_command},
    db::Database,
    models::{
        ActivityEvent, AlertFilters, AlertRecord, AlertTimelineEvent, AllowRule, AllowRuleInput,
        AppSettings, CommandExecutionResult, ConnectionCommandRequest, ConnectionEvent,
    },
};

#[tauri::command]
fn get_live_connections(state: State<'_, AppState>) -> Vec<ConnectionEvent> {
    let mut values = state.live_connections.read().values().cloned().collect::<Vec<_>>();
    values.sort_by(|left, right| right.score.cmp(&left.score).then(right.timestamp.cmp(&left.timestamp)));
    values
}

#[tauri::command]
fn subscribe_connection_events() -> &'static str {
    "monitor://connection"
}

#[tauri::command]
fn get_alerts(state: State<'_, AppState>, filters: Option<AlertFilters>) -> Result<Vec<AlertRecord>, String> {
    state
        .database
        .list_alerts(filters.unwrap_or(AlertFilters {
            statuses: None,
            risk_levels: None,
            limit: Some(100),
        }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_alert_details(state: State<'_, AppState>, id: String) -> Result<AlertRecord, String> {
    state
        .database
        .get_alert(&id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Alert not found".to_string())
}

#[tauri::command]
fn list_allow_rules(state: State<'_, AppState>) -> Result<Vec<AllowRule>, String> {
    Ok(state.allow_rules.read().clone())
}

#[tauri::command]
fn delete_allow_rule(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state
        .database
        .delete_allow_rule(&id)
        .map_err(|error| error.to_string())?;
    state.allow_rules.write().retain(|rule| rule.id != id);
    Ok(())
}

#[tauri::command]
fn update_allow_rule(
    state: State<'_, AppState>,
    id: String,
    rule: AllowRuleInput,
) -> Result<AllowRule, String> {
    let existing = state
        .allow_rules
        .read()
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
        .ok_or_else(|| "Trusted rule not found".to_string())?;

    let updated = AllowRule {
        id: existing.id,
        label: rule.label.unwrap_or(existing.label),
        enabled: rule.enabled.unwrap_or(existing.enabled),
        process_name: apply_optional_text_patch(existing.process_name, rule.process_name),
        signer: apply_optional_text_patch(existing.signer, rule.signer),
        exe_path: apply_optional_text_patch(existing.exe_path, rule.exe_path),
        sha256: apply_optional_text_patch(existing.sha256, rule.sha256),
        remote_pattern: apply_optional_text_patch(existing.remote_pattern, rule.remote_pattern),
        port: apply_optional_port_patch(existing.port, rule.port),
        protocol: apply_optional_text_patch(existing.protocol, rule.protocol),
        direction: apply_optional_text_patch(existing.direction, rule.direction),
        notes: apply_optional_text_patch(existing.notes, rule.notes),
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    state
        .database
        .update_allow_rule(&updated)
        .map_err(|error| error.to_string())?;

    let mut rules = state.allow_rules.write();
    if let Some(entry) = rules.iter_mut().find(|entry| entry.id == updated.id) {
        *entry = updated.clone();
    }

    Ok(updated)
}

#[tauri::command]
fn create_allow_rule(state: State<'_, AppState>, rule: AllowRuleInput) -> Result<AllowRule, String> {
    let AllowRuleInput {
        label,
        enabled,
        process_name,
        signer,
        exe_path,
        sha256,
        remote_pattern,
        port,
        protocol,
        direction,
        notes,
    } = rule;

    let allow_rule = AllowRule {
        id: Uuid::new_v4().to_string(),
        label: label.unwrap_or_else(|| {
            format!(
                "Trusted {}",
                flatten_optional_text_input(process_name.clone())
                    .unwrap_or_else(|| "pattern".to_string())
            )
        }),
        enabled: enabled.unwrap_or(true),
        process_name: flatten_optional_text_input(process_name),
        signer: flatten_optional_text_input(signer),
        exe_path: flatten_optional_text_input(exe_path),
        sha256: flatten_optional_text_input(sha256),
        remote_pattern: flatten_optional_text_input(remote_pattern),
        port: port.flatten(),
        protocol: flatten_optional_text_input(protocol),
        direction: flatten_optional_text_input(direction),
        notes: flatten_optional_text_input(notes),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    state
        .database
        .save_allow_rule(&allow_rule)
        .map_err(|error| error.to_string())?;
    state.allow_rules.write().insert(0, allow_rule.clone());
    Ok(allow_rule)
}

#[tauri::command]
fn dismiss_alert(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let alert_before = state
        .database
        .get_alert(&id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Alert not found".to_string())?;

    state
        .database
        .dismiss_alert(&id)
        .map_err(|error| error.to_string())?;
    if let Some(updated) = state
        .database
        .get_alert(&id)
        .map_err(|error| error.to_string())?
    {
        let timeline_event = AlertTimelineEvent {
            id: Uuid::new_v4().to_string(),
            alert_id: updated.id.clone(),
            timestamp: Utc::now(),
            event_type: "dismissed".to_string(),
            status: "dismissed".to_string(),
            risk_level: updated.risk_level.clone(),
            score: updated.score,
            confidence: updated.confidence,
            occurrence_count: updated.occurrence_count,
            summary: format!(
                "Alert dismissed after {} occurrence(s). Previous status was {}.",
                updated.occurrence_count, alert_before.status
            ),
        };
        let _ = state.database.append_alert_timeline_event(&timeline_event);
    }
    state
        .active_alerts
        .write()
        .retain(|_, alert| alert.id != id);
    Ok(())
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    Ok(state.settings.read().clone())
}

#[tauri::command]
fn update_settings(state: State<'_, AppState>, settings: AppSettings) -> Result<AppSettings, String> {
    state
        .database
        .save_settings(&settings)
        .map_err(|error| error.to_string())?;
    *state.settings.write() = settings.clone();
    Ok(settings)
}

#[tauri::command]
fn get_established_connections() -> Result<CommandExecutionResult, String> {
    get_established_connections_report().map_err(|error| error.to_string())
}

#[tauri::command]
fn get_recent_activity(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<ActivityEvent>, String> {
    state
        .database
        .list_activity_events(limit.unwrap_or(200).clamp(1, 500))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_alert_timeline(
    state: State<'_, AppState>,
    id: String,
    limit: Option<usize>,
) -> Result<Vec<AlertTimelineEvent>, String> {
    state
        .database
        .list_alert_timeline(&id, limit.unwrap_or(50).clamp(1, 200))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn execute_connection_command(
    request: ConnectionCommandRequest,
) -> Result<CommandExecutionResult, String> {
    run_connection_command(&request).map_err(|error| error.to_string())
}

fn sanitize_text(value: String) -> Option<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn flatten_optional_text_input(value: Option<Option<String>>) -> Option<String> {
    value.and_then(|inner| inner.and_then(sanitize_text))
}

fn apply_optional_text_patch(
    existing: Option<String>,
    update: Option<Option<String>>,
) -> Option<String> {
    match update {
        Some(value) => value.and_then(sanitize_text),
        None => existing,
    }
}

fn apply_optional_port_patch(existing: Option<u16>, update: Option<Option<u16>>) -> Option<u16> {
    match update {
        Some(value) => value,
        None => existing,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_dir = app
                .path()
                .app_data_dir()
                .or_else(|_| std::env::current_dir())?;
            let database = Database::new(app_dir.join("sentinel-desk.db"))?;
            let allow_rules = database.list_allow_rules()?;
            let settings = database.load_settings()?;
            let baselines = database.load_baselines()?;
            let active_alerts = database.list_active_alerts()?;
            let state = AppState::new(database, allow_rules, settings, baselines, active_alerts);
            monitor::start_monitor(app.handle().clone(), state.clone());
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_live_connections,
            subscribe_connection_events,
            get_alerts,
            get_alert_details,
            list_allow_rules,
            delete_allow_rule,
            update_allow_rule,
            create_allow_rule,
            dismiss_alert,
            get_settings,
            update_settings,
            get_established_connections,
            get_recent_activity,
            get_alert_timeline,
            execute_connection_command
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
