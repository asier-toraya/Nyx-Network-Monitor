mod classifier;
mod command_runner;
mod db;
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
        ActivityEvent, AlertFilters, AlertRecord, AllowRule, AllowRuleInput, AppSettings,
        CommandExecutionResult, ConnectionCommandRequest, ConnectionEvent,
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
fn create_allow_rule(state: State<'_, AppState>, rule: AllowRuleInput) -> Result<AllowRule, String> {
    let allow_rule = AllowRule {
        id: Uuid::new_v4().to_string(),
        label: rule
            .label
            .unwrap_or_else(|| format!("Trusted {}", rule.process_name.clone().unwrap_or_else(|| "pattern".to_string()))),
        process_name: rule.process_name,
        signer: rule.signer,
        exe_path: rule.exe_path,
        sha256: rule.sha256,
        remote_pattern: rule.remote_pattern,
        port: rule.port,
        protocol: rule.protocol,
        direction: rule.direction,
        created_at: Utc::now(),
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
    state
        .database
        .dismiss_alert(&id)
        .map_err(|error| error.to_string())?;
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
fn execute_connection_command(
    request: ConnectionCommandRequest,
) -> Result<CommandExecutionResult, String> {
    run_connection_command(&request).map_err(|error| error.to_string())
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
            create_allow_rule,
            dismiss_alert,
            get_settings,
            update_settings,
            get_established_connections,
            get_recent_activity,
            execute_connection_command
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
