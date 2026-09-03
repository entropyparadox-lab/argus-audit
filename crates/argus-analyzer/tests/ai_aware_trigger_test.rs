use argus_analyzer::{
    AiAwareTriggerEvaluator, SessionType, SessionWatcher, TelegramConfig, TriggerConfig,
    TriggerReason,
};
use argus_collector::AuditStore;
use argus_common::events::{AuditEvent, KeystrokeInput, SessionEnd, SessionInit};
use chrono::{Duration, Utc};
use uuid::Uuid;

#[test]
fn test_ai_aware_dynamic_idle_3m_vs_15m() {
    let sid_shell = Uuid::new_v4();
    let sid_ai = Uuid::new_v4();
    let config = TriggerConfig::from_mins(3, 15);
    let start = Utc::now() - Duration::minutes(30);

    // 1. Regular Shell Session
    let shell_events = vec![
        AuditEvent::SessionInit(SessionInit {
            session_id: sid_shell,
            timestamp: start,
            hostname: "prod-node-01".into(),
            username: "alice".into(),
            tty: "ttys001".into(),
            client_ip: Some("198.51.100.1".into()),
            client_port: Some(50001),
            ssh_key_fingerprint: None,
            ssh_key_comment: Some("alice@workstation".into()),
            env_context: None,
        }),
        AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid_shell,
                1,
                100,
                b"git checkout -b feat/payments\n".to_vec(),
                true,
            )
            .with_timestamp(start),
        ),
    ];

    // Check after 4 minutes (threshold: 3m) -> Should fire for shell
    let eval_shell = AiAwareTriggerEvaluator::evaluate(
        sid_shell,
        start,
        &shell_events,
        0,
        start + Duration::minutes(4),
        &config,
    );
    assert!(eval_shell.should_notify);
    assert_eq!(eval_shell.session_type, SessionType::ShellSession);
    match eval_shell.trigger_reason {
        Some(TriggerReason::IdleTimeout { threshold_secs, .. }) => {
            assert_eq!(threshold_secs, 180);
        }
        other => panic!("Expected IdleTimeout(180s), got {:?}", other),
    }

    // 2. Claude AI Session
    let ai_events = vec![
        AuditEvent::SessionInit(SessionInit {
            session_id: sid_ai,
            timestamp: start,
            hostname: "prod-node-01".into(),
            username: "alice".into(),
            tty: "ttys002".into(),
            client_ip: Some("198.51.100.1".into()),
            client_port: Some(50002),
            ssh_key_fingerprint: None,
            ssh_key_comment: Some("alice@workstation".into()),
            env_context: None,
        }),
        AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid_ai,
                1,
                100,
                b"claude 'Design resilient payment retry mechanism'\n".to_vec(),
                true,
            )
            .with_timestamp(start),
        ),
    ];

    // Check after 5 minutes -> Should NOT fire for Claude session (thinking / executing)
    let eval_ai_5m = AiAwareTriggerEvaluator::evaluate(
        sid_ai,
        start,
        &ai_events,
        0,
        start + Duration::minutes(5),
        &config,
    );
    assert!(!eval_ai_5m.should_notify);
    assert!(eval_ai_5m.session_type.is_ai());

    // Check after 16 minutes -> SHOULD fire for Claude session (threshold: 15m)
    let eval_ai_16m = AiAwareTriggerEvaluator::evaluate(
        sid_ai,
        start,
        &ai_events,
        0,
        start + Duration::minutes(16),
        &config,
    );
    assert!(eval_ai_16m.should_notify);
    assert!(eval_ai_16m.session_type.is_ai());
    match eval_ai_16m.trigger_reason {
        Some(TriggerReason::IdleTimeout { threshold_secs, .. }) => {
            assert_eq!(threshold_secs, 900);
        }
        other => panic!("Expected IdleTimeout(900s), got {:?}", other),
    }
}

#[test]
fn test_ssh_client_disconnect_trigger() {
    let sid = Uuid::new_v4();
    let config = TriggerConfig::from_mins(3, 15);
    let start = Utc::now() - Duration::minutes(10);

    let events = vec![
        AuditEvent::SessionInit(SessionInit {
            session_id: sid,
            timestamp: start,
            hostname: "prod-node-02".into(),
            username: "deployer".into(),
            tty: "pts/3".into(),
            client_ip: Some("198.51.100.2".into()),
            client_port: Some(51234),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        }),
        AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid,
                1,
                100,
                b"claude 'Refactor worker threads'\n".to_vec(),
                true,
            )
            .with_timestamp(start),
        ),
        AuditEvent::SessionEnd(SessionEnd {
            session_id: sid,
            timestamp: start + Duration::minutes(2),
            duration_ms: 120_000,
            total_input_bytes: 35,
            exit_status: Some(0),
        }),
    ];

    // Evaluate immediately upon SSH disconnect (2 min after start)
    let eval = AiAwareTriggerEvaluator::evaluate(
        sid,
        start,
        &events,
        0,
        start + Duration::minutes(2),
        &config,
    );

    assert!(eval.should_notify);
    assert!(eval.session_type.is_ai());
    match eval.trigger_reason {
        Some(TriggerReason::ClientDisconnect { .. }) => {}
        other => panic!("Expected ClientDisconnect trigger, got {:?}", other),
    }
}

#[tokio::test]
async fn test_task_batching_and_delta_rollup() {
    let store = AuditStore::new_in_memory().unwrap();
    let sid = Uuid::new_v4();
    let start = Utc::now() - Duration::minutes(40);

    let init = AuditEvent::SessionInit(SessionInit {
        session_id: sid,
        timestamp: start,
        hostname: "prod-node-01".into(),
        username: "alice".into(),
        tty: "ttys003".into(),
        client_ip: Some("198.51.100.1".into()),
        client_port: Some(54321),
        ssh_key_fingerprint: None,
        ssh_key_comment: Some("alice@workstation".into()),
        env_context: None,
    });

    // Burst 1: Initial feature setup
    let burst_1 = AuditEvent::KeystrokeInput(
        KeystrokeInput::new(
            sid,
            1,
            100,
            b"git checkout -b feat/delta-audit\ncargo check\n".to_vec(),
            true,
        )
        .with_timestamp(start),
    );

    store.insert_batch(&[init, burst_1]).unwrap();

    let trigger_config = TriggerConfig::from_mins(3, 15);
    let telegram_config = TelegramConfig {
        bot_token: None, // dry run
        chat_id: Some("test".into()),
        thread_id: None,
        server_name: Some("prod-node-01".into()),
    };

    let watcher = SessionWatcher::new(
        store.clone(),
        trigger_config.clone(),
        telegram_config.clone(),
        false,
    );

    // 1. Check Burst 1 (idle > 3m) -> triggers 1 report
    let reports_1 = watcher.check_all_sessions().await.unwrap();
    assert_eq!(reports_1.len(), 1);
    assert_eq!(reports_1[0].key_activities.len(), 2);
    assert!(reports_1[0].key_activities[0].contains("git checkout"));

    let seq_after_burst_1 = store.get_last_notified_seq(sid).unwrap();
    assert!(seq_after_burst_1 > 0);

    // 2. Next cycle with no new activity -> 0 reports (deduplicated)
    let reports_idle = watcher.check_all_sessions().await.unwrap();
    assert_eq!(reports_idle.len(), 0);

    // Burst 2: Later in the day, developer performs test and commit
    let burst_2_time = start + Duration::minutes(20);
    let burst_2 = AuditEvent::KeystrokeInput(
        KeystrokeInput::new(
            sid,
            2,
            200,
            b"cargo test\ngit commit -am 'Add delta audit'\n".to_vec(),
            true,
        )
        .with_timestamp(burst_2_time),
    );

    store.insert_batch(&[burst_2]).unwrap();

    // 3. Check Burst 2 after idle -> Should trigger delta-only report
    let reports_2 = watcher.check_all_sessions().await.unwrap();
    assert_eq!(reports_2.len(), 1);
    // Should ONLY contain cargo test and git commit, NOT the earlier git checkout!
    assert_eq!(reports_2[0].key_activities.len(), 2);
    assert!(reports_2[0].key_activities[0].contains("cargo test"));
    assert!(reports_2[0].key_activities[1].contains("git commit"));
}

#[test]
fn test_noise_filtering() {
    let sid = Uuid::new_v4();
    let config = TriggerConfig::default();
    let start = Utc::now();

    // Trivial ping command `w`
    let ping_event = AuditEvent::KeystrokeInput(
        KeystrokeInput::new(sid, 1, 50, b"w\n".to_vec(), false).with_timestamp(start),
    );

    let eval = AiAwareTriggerEvaluator::evaluate(
        sid,
        start,
        &[ping_event],
        0,
        start + Duration::minutes(5),
        &config,
    );

    assert!(!eval.should_notify);
    assert!(eval.is_noise);
}
