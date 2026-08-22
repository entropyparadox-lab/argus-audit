use argus_collector::{AuditStore, CollectorServer};
use argus_common::codec::serialize_and_compress_events;
use argus_common::events::{AuditEvent, KeystrokeInput, SessionEnd, SessionInit};
use chrono::Utc;
use reqwest::Client;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
async fn test_e2e_agent_to_collector_pipeline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("test_audit.db");

    let store = AuditStore::new(&db_path).unwrap();
    let _server = CollectorServer::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let (event_tx, _) = tokio::sync::broadcast::channel(1024);
    let router = CollectorServer::build_router(argus_collector::server::AppState {
        store: store.clone(),
        event_tx,
        killed_sessions: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashSet::new(),
        )),
    });

    // Spawn collector server in background task
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Wait briefly for server ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Client::new();
    let health_resp = client
        .get(format!("http://{local_addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(health_resp.status(), reqwest::StatusCode::OK);

    // Prepare simulated developer session with paste and keystrokes
    let session_id = Uuid::new_v4();
    let init_event = AuditEvent::SessionInit(SessionInit {
        session_id,
        timestamp: Utc::now(),
        hostname: "dev-cluster-node1".into(),
        username: "ubuntu".into(),
        tty: "pts/3".into(),
        client_ip: Some("203.0.113.42".into()),
        client_port: Some(51234),
        ssh_key_fingerprint: Some("SHA256:4kF9x9LzQp0...".into()),
        ssh_key_comment: Some("lead_architect@company.com".into()),
        env_context: None,
    });

    let key_events: Vec<AuditEvent> = vec![
        AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            100,
            b"cat << 'EOF' > test.sql\n".to_vec(),
            false,
        )),
        AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            2,
            250,
            b"SELECT * FROM sensitive_users WHERE role = 'admin';\nEOF\n".to_vec(),
            true, // Multiline Paste
        )),
    ];

    let end_event = AuditEvent::SessionEnd(SessionEnd {
        session_id,
        timestamp: Utc::now(),
        duration_ms: 1250,
        total_input_bytes: 80,
        exit_status: Some(0),
    });

    let mut all_events = vec![init_event];
    all_events.extend(key_events);
    all_events.push(end_event);

    // Compress with Zstd and upload to collector
    let compressed_payload = serialize_and_compress_events(&all_events, 3).unwrap();
    let upload_resp = client
        .post(format!("http://{local_addr}/api/v1/events"))
        .header("Content-Type", "application/octet-stream")
        .header("Content-Encoding", "zstd")
        .body(compressed_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(upload_resp.status(), reqwest::StatusCode::ACCEPTED);

    // Verify stored session and events in Collector DB
    let sessions = store.list_sessions(10).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id);
    assert_eq!(sessions[0].client_ip, Some("203.0.113.42".into()));
    assert_eq!(
        sessions[0].ssh_key_comment,
        Some("lead_architect@company.com".into())
    );
    assert_eq!(sessions[0].duration_ms, Some(1250));

    let saved_events = store.get_session_events(session_id).unwrap();
    assert_eq!(saved_events.len(), 4);
}
