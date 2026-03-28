use std::{fs, path::PathBuf};

use anyhow::Context;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use crate::models::{
    ActivityEvent, AlertFilters, AlertRecord, AlertTimelineEvent, AllowRule, AppSettings,
    ConnectionEvent, DestinationInfo, ReputationInfo, TrafficBaseline,
};

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let database = Self { path };
        database.initialize()?;
        Ok(database)
    }

    pub fn initialize(&self) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS allow_rules (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                process_name TEXT,
                signer TEXT,
                exe_path TEXT,
                sha256 TEXT,
                remote_pattern TEXT,
                port INTEGER,
                protocol TEXT,
                direction TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connection_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                direction TEXT NOT NULL,
                local_address TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_address TEXT,
                remote_port INTEGER,
                state TEXT NOT NULL,
                pid INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                score INTEGER NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 50,
                baseline_hits INTEGER NOT NULL DEFAULT 0,
                process_json TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                reputation_json TEXT,
                suggested_firewall_rule TEXT,
                is_new INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                alert_key TEXT NOT NULL,
                connection_event_id TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                score INTEGER NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 50,
                reasons_json TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                connection_json TEXT
            );
            CREATE TABLE IF NOT EXISTS reputation_cache (
                ip TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS destination_cache (
                ip TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS baseline_patterns (
                pattern_key TEXT PRIMARY KEY,
                summary TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                change_type TEXT NOT NULL,
                connection_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_timeline_events (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                score INTEGER NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 50,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                summary TEXT NOT NULL
            );
            "#,
        )?;

        ensure_column(&connection, "allow_rules", "enabled", "INTEGER NOT NULL DEFAULT 1")?;
        ensure_column(&connection, "allow_rules", "exe_path", "TEXT")?;
        ensure_column(&connection, "allow_rules", "sha256", "TEXT")?;
        ensure_column(&connection, "allow_rules", "notes", "TEXT")?;
        ensure_column(
            &connection,
            "allow_rules",
            "updated_at",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        ensure_column(&connection, "connection_events", "confidence", "INTEGER NOT NULL DEFAULT 50")?;
        ensure_column(&connection, "connection_events", "baseline_hits", "INTEGER NOT NULL DEFAULT 0")?;
        ensure_column(&connection, "alerts", "alert_key", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&connection, "alerts", "confidence", "INTEGER NOT NULL DEFAULT 50")?;
        ensure_column(&connection, "alerts", "updated_at", "TEXT NOT NULL DEFAULT ''")?;
        ensure_column(&connection, "alerts", "occurrence_count", "INTEGER NOT NULL DEFAULT 1")?;
        Ok(())
    }

    pub fn load_settings(&self) -> anyhow::Result<AppSettings> {
        let connection = self.connection()?;
        let raw = connection
            .query_row("SELECT data FROM settings WHERE id = 1", [], |row| row.get::<_, String>(0))
            .optional()?;
        match raw {
            Some(value) => parse_settings_with_defaults(&value),
            None => {
                let defaults = AppSettings::default();
                self.save_settings(&defaults)?;
                Ok(defaults)
            }
        }
    }

    pub fn save_settings(&self, settings: &AppSettings) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO settings (id, data) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            params![serde_json::to_string(settings)?],
        )?;
        Ok(())
    }

    pub fn save_allow_rule(&self, rule: &AllowRule) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO allow_rules
                (id, label, enabled, process_name, signer, exe_path, sha256, remote_pattern, port, protocol, direction, notes, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                rule.id,
                rule.label,
                rule.enabled as i64,
                rule.process_name,
                rule.signer,
                rule.exe_path,
                rule.sha256,
                rule.remote_pattern,
                rule.port,
                rule.protocol,
                rule.direction,
                rule.notes,
                rule.created_at.to_rfc3339(),
                rule.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn update_allow_rule(&self, rule: &AllowRule) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE allow_rules SET
                label = ?2,
                enabled = ?3,
                process_name = ?4,
                signer = ?5,
                exe_path = ?6,
                sha256 = ?7,
                remote_pattern = ?8,
                port = ?9,
                protocol = ?10,
                direction = ?11,
                notes = ?12,
                updated_at = ?13
             WHERE id = ?1",
            params![
                rule.id,
                rule.label,
                rule.enabled as i64,
                rule.process_name,
                rule.signer,
                rule.exe_path,
                rule.sha256,
                rule.remote_pattern,
                rule.port,
                rule.protocol,
                rule.direction,
                rule.notes,
                rule.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_allow_rules(&self) -> anyhow::Result<Vec<AllowRule>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, label, enabled, process_name, signer, exe_path, sha256, remote_pattern, port, protocol, direction, notes, created_at, updated_at
             FROM allow_rules ORDER BY created_at DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AllowRule {
                id: row.get(0)?,
                label: row.get(1)?,
                enabled: row.get::<_, Option<i64>>(2)?.unwrap_or(1) != 0,
                process_name: row.get(3)?,
                signer: row.get(4)?,
                exe_path: row.get(5)?,
                sha256: row.get(6)?,
                remote_pattern: row.get(7)?,
                port: row.get(8)?,
                protocol: row.get(9)?,
                direction: row.get(10)?,
                notes: row.get(11)?,
                created_at: parse_datetime(row.get::<_, String>(12)?),
                updated_at: parse_datetime(
                    row.get::<_, Option<String>>(13)?
                        .unwrap_or_else(|| row.get::<_, String>(12).unwrap_or_default()),
                ),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn delete_allow_rule(&self, id: &str) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute("DELETE FROM allow_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn save_connection_event(&self, event: &ConnectionEvent) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO connection_events
                (id, timestamp, protocol, direction, local_address, local_port, remote_address, remote_port,
                 state, pid, risk_level, score, confidence, baseline_hits, process_json, reasons_json,
                 reputation_json, suggested_firewall_rule, is_new)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
             ON CONFLICT(id) DO UPDATE SET
                timestamp = excluded.timestamp,
                direction = excluded.direction,
                state = excluded.state,
                risk_level = excluded.risk_level,
                score = excluded.score,
                confidence = excluded.confidence,
                baseline_hits = excluded.baseline_hits,
                process_json = excluded.process_json,
                reasons_json = excluded.reasons_json,
                reputation_json = excluded.reputation_json,
                suggested_firewall_rule = excluded.suggested_firewall_rule,
                is_new = excluded.is_new",
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                event.protocol,
                event.direction,
                event.local_address,
                event.local_port,
                event.remote_address,
                event.remote_port,
                event.state,
                event.pid,
                serde_json::to_string(&event.risk_level)?,
                event.score,
                event.confidence,
                event.baseline_hits,
                serde_json::to_string(&event.process)?,
                serde_json::to_string(&event.reasons)?,
                event.reputation
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                event.suggested_firewall_rule,
                event.is_new as i64,
            ],
        )?;
        Ok(())
    }

    pub fn append_activity_event(&self, event: &ActivityEvent) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO activity_events (id, timestamp, change_type, connection_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                event.change_type,
                serde_json::to_string(&event.connection)?,
            ],
        )?;
        Ok(())
    }

    pub fn list_activity_events(&self, limit: usize) -> anyhow::Result<Vec<ActivityEvent>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, timestamp, change_type, connection_json
             FROM activity_events
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            let payload = row.get::<_, String>(3)?;
            Ok(ActivityEvent {
                id: row.get(0)?,
                timestamp: parse_datetime(row.get::<_, String>(1)?),
                change_type: row.get(2)?,
                connection: serde_json::from_str(&payload).unwrap(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn append_alert_timeline_event(&self, event: &AlertTimelineEvent) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO alert_timeline_events
                (id, alert_id, timestamp, event_type, status, risk_level, score, confidence, occurrence_count, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.id,
                event.alert_id,
                event.timestamp.to_rfc3339(),
                event.event_type,
                event.status,
                serde_json::to_string(&event.risk_level)?,
                event.score,
                event.confidence,
                event.occurrence_count,
                event.summary,
            ],
        )?;
        Ok(())
    }

    pub fn list_alert_timeline(
        &self,
        alert_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<AlertTimelineEvent>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, alert_id, timestamp, event_type, status, risk_level, score, confidence, occurrence_count, summary
             FROM alert_timeline_events
             WHERE alert_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![alert_id, limit as i64], |row| {
            Ok(AlertTimelineEvent {
                id: row.get(0)?,
                alert_id: row.get(1)?,
                timestamp: parse_datetime(row.get::<_, String>(2)?),
                event_type: row.get(3)?,
                status: row.get(4)?,
                risk_level: serde_json::from_str(&row.get::<_, String>(5)?).unwrap(),
                score: row.get(6)?,
                confidence: row.get::<_, Option<i32>>(7)?.unwrap_or(50),
                occurrence_count: row.get::<_, Option<u32>>(8)?.unwrap_or(1),
                summary: row.get(9)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn save_alert(&self, alert: &AlertRecord) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO alerts
                (id, alert_key, connection_event_id, risk_level, score, confidence, reasons_json,
                 recommended_action, status, created_at, updated_at, occurrence_count, connection_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
                alert_key = excluded.alert_key,
                connection_event_id = excluded.connection_event_id,
                risk_level = excluded.risk_level,
                score = excluded.score,
                confidence = excluded.confidence,
                reasons_json = excluded.reasons_json,
                recommended_action = excluded.recommended_action,
                status = excluded.status,
                updated_at = excluded.updated_at,
                occurrence_count = excluded.occurrence_count,
                connection_json = excluded.connection_json",
            params![
                alert.id,
                alert.alert_key,
                alert.connection_event_id,
                serde_json::to_string(&alert.risk_level)?,
                alert.score,
                alert.confidence,
                serde_json::to_string(&alert.reasons)?,
                alert.recommended_action,
                alert.status,
                alert.created_at.to_rfc3339(),
                alert.updated_at.to_rfc3339(),
                alert.occurrence_count,
                alert.connection.as_ref().map(serde_json::to_string).transpose()?,
            ],
        )?;
        Ok(())
    }

    pub fn list_alerts(&self, filters: AlertFilters) -> anyhow::Result<Vec<AlertRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, alert_key, connection_event_id, risk_level, score, confidence, reasons_json,
                    recommended_action, status, created_at, updated_at, occurrence_count, connection_json
             FROM alerts ORDER BY updated_at DESC, created_at DESC",
        )?;
        let rows = statement.query_map([], |row| self.map_alert_row(row))?;
        let mut records = rows.collect::<Result<Vec<_>, _>>()?;
        if let Some(statuses) = filters.statuses {
            records.retain(|alert| statuses.iter().any(|value| value == &alert.status));
        }
        if let Some(levels) = filters.risk_levels {
            records.retain(|alert| levels.iter().any(|value| value == &alert.risk_level));
        }
        if let Some(limit) = filters.limit {
            records.truncate(limit);
        }
        Ok(records)
    }

    pub fn list_active_alerts(&self) -> anyhow::Result<Vec<AlertRecord>> {
        self.list_alerts(AlertFilters {
            statuses: Some(vec!["new".to_string(), "open".to_string()]),
            risk_levels: None,
            limit: None,
        })
    }

    pub fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, alert_key, connection_event_id, risk_level, score, confidence, reasons_json,
                    recommended_action, status, created_at, updated_at, occurrence_count, connection_json
             FROM alerts WHERE id = ?1",
        )?;
        let record = statement
            .query_row(params![id], |row| self.map_alert_row(row))
            .optional()?;
        Ok(record)
    }

    pub fn dismiss_alert(&self, id: &str) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "UPDATE alerts SET status = 'dismissed', updated_at = ?2 WHERE id = ?1",
            params![id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn load_baselines(&self) -> anyhow::Result<Vec<TrafficBaseline>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT pattern_key, summary, first_seen, last_seen, hit_count
             FROM baseline_patterns ORDER BY last_seen DESC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(TrafficBaseline {
                pattern_key: row.get(0)?,
                summary: row.get(1)?,
                first_seen: parse_datetime(row.get::<_, String>(2)?),
                last_seen: parse_datetime(row.get::<_, String>(3)?),
                hit_count: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn touch_baseline(
        &self,
        pattern_key: &str,
        summary: &str,
        seen_at: DateTime<Utc>,
    ) -> anyhow::Result<TrafficBaseline> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO baseline_patterns (pattern_key, summary, first_seen, last_seen, hit_count)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT(pattern_key) DO UPDATE SET
                summary = excluded.summary,
                last_seen = excluded.last_seen,
                hit_count = baseline_patterns.hit_count + 1",
            params![pattern_key, summary, seen_at.to_rfc3339(), seen_at.to_rfc3339()],
        )?;

        connection.query_row(
            "SELECT pattern_key, summary, first_seen, last_seen, hit_count
             FROM baseline_patterns WHERE pattern_key = ?1",
            params![pattern_key],
            |row| {
                Ok(TrafficBaseline {
                    pattern_key: row.get(0)?,
                    summary: row.get(1)?,
                    first_seen: parse_datetime(row.get::<_, String>(2)?),
                    last_seen: parse_datetime(row.get::<_, String>(3)?),
                    hit_count: row.get(4)?,
                })
            },
        ).map_err(Into::into)
    }

    pub fn get_cached_reputation(&self, ip: &str) -> anyhow::Result<Option<ReputationInfo>> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT value_json, expires_at FROM reputation_cache WHERE ip = ?1",
                params![ip],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        let Some((value_json, expires_at)) = row else {
            return Ok(None);
        };

        if parse_datetime(expires_at) < Utc::now() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_str(&value_json)?))
    }

    pub fn get_cached_destination(&self, ip: &str) -> anyhow::Result<Option<DestinationInfo>> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT value_json, expires_at FROM destination_cache WHERE ip = ?1",
                params![ip],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        let Some((value_json, expires_at)) = row else {
            return Ok(None);
        };

        if parse_datetime(expires_at) < Utc::now() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_str(&value_json)?))
    }

    pub fn set_cached_reputation(
        &self,
        ip: &str,
        value: &ReputationInfo,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO reputation_cache (ip, value_json, expires_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(ip) DO UPDATE SET
                value_json = excluded.value_json,
                expires_at = excluded.expires_at",
            params![ip, serde_json::to_string(value)?, expires_at.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn set_cached_destination(
        &self,
        ip: &str,
        value: &DestinationInfo,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO destination_cache (ip, value_json, expires_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(ip) DO UPDATE SET
                value_json = excluded.value_json,
                expires_at = excluded.expires_at",
            params![ip, serde_json::to_string(value)?, expires_at.to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn prune(&self, retention_days: u32) -> anyhow::Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let connection = self.connection()?;
        connection.execute(
            "DELETE FROM alerts WHERE updated_at < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        connection.execute(
            "DELETE FROM connection_events WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        connection.execute(
            "DELETE FROM activity_events WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        connection.execute(
            "DELETE FROM reputation_cache WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        connection.execute(
            "DELETE FROM destination_cache WHERE expires_at < ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        connection.execute(
            "DELETE FROM alert_timeline_events WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        )?;
        Ok(())
    }

    fn connection(&self) -> anyhow::Result<Connection> {
        Connection::open(&self.path).with_context(|| format!("opening sqlite db {:?}", self.path))
    }

    fn map_alert_row(&self, row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRecord> {
        let updated_at = row
            .get::<_, Option<String>>(10)?
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| row.get::<_, String>(9).unwrap_or_default());

        Ok(AlertRecord {
            id: row.get(0)?,
            alert_key: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            connection_event_id: row.get(2)?,
            risk_level: serde_json::from_str(&row.get::<_, String>(3)?).unwrap(),
            score: row.get(4)?,
            confidence: row.get::<_, Option<i32>>(5)?.unwrap_or(50),
            reasons: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
            recommended_action: row.get(7)?,
            status: row.get(8)?,
            created_at: parse_datetime(row.get::<_, String>(9)?),
            updated_at: parse_datetime(updated_at),
            occurrence_count: row.get::<_, Option<u32>>(11)?.unwrap_or(1),
            connection: row
                .get::<_, Option<String>>(12)?
                .and_then(|value| serde_json::from_str(&value).ok()),
        })
    }
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    column_sql: &str,
) -> anyhow::Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let has_column = columns
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|name| name == column);

    if !has_column {
        connection.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {column_sql}"),
            [],
        )?;
    }

    Ok(())
}

fn parse_datetime(value: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_settings_with_defaults(value: &str) -> anyhow::Result<AppSettings> {
    let mut parsed: serde_json::Value =
        serde_json::from_str(value).context("parsing settings json")?;
    let defaults = serde_json::to_value(AppSettings::default())?;
    merge_json_defaults(&mut parsed, &defaults);
    serde_json::from_value(parsed).context("parsing settings json")
}

fn merge_json_defaults(target: &mut serde_json::Value, defaults: &serde_json::Value) {
    if let serde_json::Value::Object(default_map) = defaults {
        if let serde_json::Value::Object(target_map) = target {
            for (key, default_value) in default_map {
                match target_map.get_mut(key) {
                    Some(existing) => merge_json_defaults(existing, default_value),
                    None => {
                        target_map.insert(key.clone(), default_value.clone());
                    }
                }
            }
            return;
        }
    }

    if target.is_null() {
        *target = defaults.clone();
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::tempdir;

    use super::Database;
    use crate::models::{
        ActivityEvent, AlertRecord, AllowRule, AppSettings, ConnectionEvent, ProcessIdentity,
        RiskLevel, RiskReason,
    };

    #[test]
    fn settings_round_trip() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        let settings = AppSettings {
            polling_interval_secs: 5,
            ..AppSettings::default()
        };
        db.save_settings(&settings).unwrap();
        let loaded = db.load_settings().unwrap();
        assert_eq!(loaded.polling_interval_secs, 5);
    }

    #[test]
    fn allow_rules_round_trip() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        db.save_allow_rule(&AllowRule {
            id: "1".to_string(),
            label: "Trusted".to_string(),
            enabled: true,
            process_name: Some("ssh.exe".to_string()),
            signer: None,
            exe_path: Some("C:\\Windows\\System32\\OpenSSH\\ssh.exe".to_string()),
            sha256: Some("abc".to_string()),
            remote_pattern: Some("10.0.0.4".to_string()),
            port: Some(22),
            protocol: Some("tcp".to_string()),
            direction: Some("outgoing".to_string()),
            notes: Some("analyst note".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .unwrap();

        let rules = db.list_allow_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].label, "Trusted");
        assert!(rules[0].enabled);
        assert_eq!(rules[0].sha256.as_deref(), Some("abc"));
        assert_eq!(rules[0].notes.as_deref(), Some("analyst note"));
    }

    #[test]
    fn allow_rule_can_be_deleted() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        db.save_allow_rule(&AllowRule {
            id: "1".to_string(),
            label: "Trusted".to_string(),
            enabled: true,
            process_name: Some("ssh.exe".to_string()),
            signer: None,
            exe_path: None,
            sha256: None,
            remote_pattern: None,
            port: None,
            protocol: None,
            direction: None,
            notes: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
        .unwrap();

        db.delete_allow_rule("1").unwrap();
        assert!(db.list_allow_rules().unwrap().is_empty());
    }

    #[test]
    fn baseline_touch_increments() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        let first = db
            .touch_baseline("ssh:22", "ssh.exe / tcp / outgoing / 22", Utc::now())
            .unwrap();
        let second = db
            .touch_baseline("ssh:22", "ssh.exe / tcp / outgoing / 22", Utc::now())
            .unwrap();
        assert_eq!(first.hit_count, 1);
        assert_eq!(second.hit_count, 2);
    }

    #[test]
    fn active_alerts_are_loaded() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        db.save_alert(&AlertRecord {
            id: "a1".to_string(),
            alert_key: "key".to_string(),
            connection_event_id: "c1".to_string(),
            risk_level: RiskLevel::Unknown,
            score: 12,
            confidence: 65,
            reasons: vec![RiskReason {
                code: "test".to_string(),
                message: "test".to_string(),
            }],
            recommended_action: "Review".to_string(),
            status: "open".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            occurrence_count: 2,
            connection: None,
        })
        .unwrap();
        let alerts = db.list_active_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].occurrence_count, 2);
    }

    #[test]
    fn activity_events_round_trip() {
        let dir = tempdir().unwrap();
        let db = Database::new(dir.path().join("sentinel.db")).unwrap();
        let connection = ConnectionEvent {
            id: "c1".to_string(),
            timestamp: Utc::now(),
            protocol: "tcp".to_string(),
            direction: "outgoing".to_string(),
            local_address: "127.0.0.1".to_string(),
            local_port: 50_000,
            remote_address: Some("1.1.1.1".to_string()),
            remote_port: Some(443),
            state: "Established".to_string(),
            pid: 42,
            process: ProcessIdentity {
                pid: 42,
                name: "chrome.exe".to_string(),
                exe_path: Some("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".to_string()),
                user: Some("DOMAIN\\user".to_string()),
                parent_pid: Some(1),
                parent_name: Some("explorer.exe".to_string()),
                signer: Some("Google LLC".to_string()),
                is_signed: true,
                publisher: Some("Google Trust Services".to_string()),
                sha256: Some("abc".to_string()),
                metadata_pending: false,
                hosted_services: Vec::new(),
                service_context_pending: false,
            },
            risk_level: RiskLevel::Safe,
            score: 0,
            confidence: 80,
            baseline_hits: 3,
            reasons: vec![RiskReason {
                code: "baseline_established".to_string(),
                message: "Seen before".to_string(),
            }],
            reputation: None,
            destination: None,
            suggested_firewall_rule: None,
            is_new: false,
        };

        db.append_activity_event(&ActivityEvent {
            id: "a1".to_string(),
            timestamp: Utc::now(),
            change_type: "opened".to_string(),
            connection,
        })
        .unwrap();

        let events = db.list_activity_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].change_type, "opened");
        assert_eq!(events[0].connection.process.name, "chrome.exe");
    }
}
