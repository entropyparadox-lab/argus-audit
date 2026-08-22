use anyhow::{Context, Result};
use argus_common::events::AuditEvent;
use argus_common::hash_chain::{verify_event_chain, ChainedAuditEvent, GENESIS_HASH};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct AuditStore {
    conn: Arc<Mutex<Connection>>,
}

impl AuditStore {
    /// Initialize a new Audit SQLite Store with WAL mode and strict 0700 file permissions
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path = db_path.as_ref();

        // Ensure parent directories exist with 0700 permissions
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory {:?}", parent))?;
                let mut perms = fs::metadata(parent)?.permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(parent, perms);
            }
        }

        let conn = Connection::open(path)
            .with_context(|| format!("Failed to open SQLite database at {:?}", path))?;

        // Secure file permissions (0600)
        if path.exists() {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(path, perms);
        }

        // Enable WAL mode & performance pragmas
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        store.init_schema()?;
        Ok(store)
    }

    /// Create in-memory SQLite store for testing
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                tty TEXT NOT NULL,
                client_ip TEXT,
                client_port INTEGER,
                ssh_key_fingerprint TEXT,
                ssh_key_comment TEXT,
                duration_ms INTEGER,
                total_input_bytes INTEGER,
                exit_status INTEGER
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                seq INTEGER NOT NULL DEFAULT 0,
                prev_hash TEXT NOT NULL DEFAULT '',
                hash TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload JSON NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_sessions_client_ip ON sessions(client_ip);
            CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);",
        )?;
        Ok(())
    }

    /// Batch insert audit events into SQLite with automatic cryptographic hash chaining
    pub fn insert_batch(&self, events: &[AuditEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        for event in events {
            let session_id_str = event.session_id().map(|id| id.to_string());
            let timestamp_str = event.timestamp().to_rfc3339();
            let event_type = event.event_type_name();
            let payload_json = serde_json::to_string(event)?;

            // Get last hash and seq for this session
            let (last_seq, last_hash): (u64, String) = if let Some(ref sid) = session_id_str {
                tx.query_row(
                    "SELECT seq, hash FROM events WHERE session_id = ?1 ORDER BY id DESC LIMIT 1",
                    params![sid],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or((0, GENESIS_HASH.to_string()))
            } else {
                (0, GENESIS_HASH.to_string())
            };

            let next_seq = last_seq + 1;
            let chained = ChainedAuditEvent::new(next_seq, &last_hash, event.clone());

            // If session init, record in sessions table
            if let AuditEvent::SessionInit(init) = event {
                tx.execute(
                    "INSERT OR IGNORE INTO sessions (
                        session_id, created_at, hostname, username, tty,
                        client_ip, client_port, ssh_key_fingerprint, ssh_key_comment
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        init.session_id.to_string(),
                        init.timestamp.to_rfc3339(),
                        init.hostname,
                        init.username,
                        init.tty,
                        init.client_ip,
                        init.client_port,
                        init.ssh_key_fingerprint,
                        init.ssh_key_comment,
                    ],
                )?;
            } else if let AuditEvent::SessionEnd(end) = event {
                tx.execute(
                    "UPDATE sessions SET
                        duration_ms = ?1,
                        total_input_bytes = ?2,
                        exit_status = ?3
                     WHERE session_id = ?4",
                    params![
                        end.duration_ms,
                        end.total_input_bytes,
                        end.exit_status,
                        end.session_id.to_string(),
                    ],
                )?;
            }

            // Record into events table with cryptographic hash chain and deterministic raw JSON
            let raw_json_str = chained.raw_json.unwrap_or(payload_json);
            tx.execute(
                "INSERT INTO events (session_id, seq, prev_hash, hash, event_type, timestamp, payload)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![session_id_str, chained.seq, chained.prev_hash, chained.hash, event_type, timestamp_str, raw_json_str],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Query all events for a given session in chronological order
    pub fn get_session_events(&self, session_id: Uuid) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT payload FROM events WHERE session_id = ?1 ORDER BY id ASC")?;

        let rows = stmt.query_map(params![session_id.to_string()], |row| {
            let json_str: String = row.get(0)?;
            Ok(json_str)
        })?;

        let mut events = Vec::new();
        for json_str in rows {
            let event: AuditEvent = serde_json::from_str(&json_str?)?;
            events.push(event);
        }

        Ok(events)
    }

    /// Query chained events with hashes for cryptographic verification
    pub fn get_chained_session_events(&self, session_id: Uuid) -> Result<Vec<ChainedAuditEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT seq, prev_hash, hash, payload FROM events WHERE session_id = ?1 ORDER BY id ASC",
        )?;

        let rows = stmt.query_map(params![session_id.to_string()], |row| {
            let seq: u64 = row.get(0)?;
            let prev_hash: String = row.get(1)?;
            let hash: String = row.get(2)?;
            let payload_json: String = row.get(3)?;
            ChainedAuditEvent::from_raw(seq, &prev_hash, &hash, &payload_json).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                )
            })
        })?;

        let mut chained_events = Vec::new();
        for item in rows {
            chained_events.push(item?);
        }

        Ok(chained_events)
    }

    /// Cryptographically verify session integrity
    pub fn verify_session_integrity(&self, session_id: Uuid) -> Result<()> {
        let chain = self.get_chained_session_events(session_id)?;
        verify_event_chain(&chain)
    }

    /// List recent sessions
    pub fn list_sessions(&self, limit: usize) -> Result<Vec<SessionSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, created_at, hostname, username, tty, client_ip,
                    client_port, ssh_key_comment, duration_ms, total_input_bytes, exit_status
             FROM sessions
             ORDER BY created_at DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let session_id_str: String = row.get(0)?;
            let created_at_str: String = row.get(1)?;
            Ok(SessionSummary {
                session_id: Uuid::parse_str(&session_id_str).unwrap_or_default(),
                created_at: DateTime::parse_from_rfc3339(&created_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                hostname: row.get(2)?,
                username: row.get(3)?,
                tty: row.get(4)?,
                client_ip: row.get(5)?,
                client_port: row.get(6)?,
                ssh_key_comment: row.get(7)?,
                duration_ms: row.get(8)?,
                total_input_bytes: row.get(9)?,
                exit_status: row.get(10)?,
            })
        })?;

        let mut list = Vec::new();
        for item in rows {
            list.push(item?);
        }

        Ok(list)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub hostname: String,
    pub username: String,
    pub tty: String,
    pub client_ip: Option<String>,
    pub client_port: Option<u16>,
    pub ssh_key_comment: Option<String>,
    pub duration_ms: Option<u64>,
    pub total_input_bytes: Option<u64>,
    pub exit_status: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::events::{KeystrokeInput, SessionEnd, SessionInit};

    #[test]
    fn test_store_hash_chain_verification() {
        let store = AuditStore::new_in_memory().unwrap();
        let session_id = Uuid::new_v4();

        let init = AuditEvent::SessionInit(SessionInit {
            session_id,
            timestamp: Utc::now(),
            hostname: "test-host".into(),
            username: "ubuntu".into(),
            tty: "pts/0".into(),
            client_ip: Some("192.168.1.100".into()),
            client_port: Some(44231),
            ssh_key_fingerprint: Some("SHA256:test".into()),
            ssh_key_comment: Some("dev_test@company.com".into()),
            env_context: None,
        });

        let key_1 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            50,
            b"cargo test\n".to_vec(),
            false,
        ));

        let end = AuditEvent::SessionEnd(SessionEnd {
            session_id,
            timestamp: Utc::now(),
            duration_ms: 1500,
            total_input_bytes: 11,
            exit_status: Some(0),
        });

        store.insert_batch(&[init, key_1, end]).unwrap();

        // 1. Verify mathematically intact chain
        assert!(store.verify_session_integrity(session_id).is_ok());

        let chained = store.get_chained_session_events(session_id).unwrap();
        assert_eq!(chained.len(), 3);
        assert_eq!(chained[0].seq, 1);
        assert_eq!(chained[1].seq, 2);
        assert_eq!(chained[2].seq, 3);
        assert_eq!(chained[0].prev_hash, GENESIS_HASH);
        assert_eq!(chained[1].prev_hash, chained[0].hash);
        assert_eq!(chained[2].prev_hash, chained[1].hash);
    }
}
