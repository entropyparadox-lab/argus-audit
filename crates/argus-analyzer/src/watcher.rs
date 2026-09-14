use crate::notifier::{NotificationReport, TelegramConfig, TelegramNotifier};
use crate::trigger::{AiAwareTriggerEvaluator, TriggerConfig, TriggerEvaluation, TriggerReason};
use anyhow::Result;
use argus_collector::{AuditStore, SessionSummary};
use argus_common::events::AuditEvent;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{error, info, warn};

pub struct SessionWatcher {
    store: AuditStore,
    trigger_config: TriggerConfig,
    telegram_config: TelegramConfig,
    dry_run: bool,
    recent_dispatches: Mutex<HashMap<(String, String), std::time::Instant>>,
}

impl SessionWatcher {
    pub fn new(
        store: AuditStore,
        trigger_config: TriggerConfig,
        telegram_config: TelegramConfig,
        dry_run: bool,
    ) -> Self {
        Self {
            store,
            trigger_config,
            telegram_config,
            dry_run,
            recent_dispatches: Mutex::new(HashMap::new()),
        }
    }

    /// Run one round of trigger evaluations against all recent active sessions
    pub async fn check_all_sessions(&self) -> Result<Vec<NotificationReport>> {
        let sessions = self.store.list_sessions(100)?;
        let mut dispatched_reports = Vec::new();
        let now = Utc::now();

        struct CandidateSession {
            summary: SessionSummary,
            eval: TriggerEvaluation,
            trigger_reason: TriggerReason,
            report: NotificationReport,
        }

        let mut security_candidates = Vec::new();
        let mut routine_by_host: HashMap<String, Vec<CandidateSession>> = HashMap::new();

        for s in sessions {
            let events = match self.store.get_session_events(s.session_id) {
                Ok(ev) => ev,
                Err(e) => {
                    warn!("Failed to fetch events for session {}: {e}", s.session_id);
                    continue;
                }
            };

            let last_notified_seq = self.store.get_last_notified_seq(s.session_id).unwrap_or(0);

            let eval = AiAwareTriggerEvaluator::evaluate(
                s.session_id,
                s.created_at,
                &events,
                last_notified_seq,
                now,
                &self.trigger_config,
            );

            let is_tampered = self.store.verify_session_integrity(s.session_id).is_err();
            let should_notify = eval.should_notify || (is_tampered && !eval.unnotified_events.is_empty());

            if !should_notify {
                continue;
            }

            let trigger_reason = if let Some(r) = eval.trigger_reason.clone() {
                r
            } else if is_tampered {
                TriggerReason::SecurityAnomaly {
                    alert_count: 1,
                    max_severity: "Critical (해시 체인 불일치)".to_string(),
                }
            } else {
                continue;
            };

            let init_event = events.iter().find_map(|e| match e {
                AuditEvent::SessionInit(init) => Some(init),
                _ => None,
            });

            let report = NotificationReport::build(
                s.session_id,
                init_event,
                eval.session_type.clone(),
                trigger_reason.clone(),
                &eval.unnotified_reconstructed.activities,
                &eval.unnotified_events,
                is_tampered,
            );

            let is_security = report.alert_count > 0
                || report.is_tampered
                || matches!(report.trigger_reason, TriggerReason::SecurityAnomaly { .. });

            if is_security {
                security_candidates.push((s, eval, trigger_reason, report));
            } else {
                routine_by_host
                    .entry(report.hostname.clone())
                    .or_default()
                    .push(CandidateSession {
                        summary: s,
                        eval,
                        trigger_reason,
                        report,
                    });
            }
        }

        // 1. Dispatch Security Alerts IMMEDIATELY (0-second bypass, no host cooldown or delay)
        for (s, eval, trigger_reason, report) in security_candidates {
            let summary_preview = report.key_activities.join("; ");
            if !self.dry_run {
                if let Err(e) = TelegramNotifier::send_report(&self.telegram_config, &report).await {
                    error!(
                        "Failed to dispatch security alert for session {}: {e}. Retaining checkpoint for retry.",
                        s.session_id
                    );
                } else {
                    info!(
                        "Successfully dispatched security alert for session {} (Trigger: {})",
                        s.session_id,
                        trigger_reason.display_text()
                    );
                    let _ = self.store.record_notification(
                        s.session_id,
                        eval.latest_seq,
                        &trigger_reason.display_text(),
                        eval.session_type.display_name(),
                        &summary_preview,
                    );
                }
            } else {
                info!(
                    "[DRY-RUN] Dispatched security alert for {} (Reason: {})",
                    s.session_id,
                    trigger_reason.display_text()
                );
            }
            dispatched_reports.push(report);
        }

        // 2. Process Routine Operations Grouped by Host
        for (hostname, candidates) in routine_by_host {
            // Check A: Cross-Session Host Idle Check
            // If ALL candidates only triggered IdleTimeout, check if the host as a whole is truly idle
            let all_idle = candidates.iter().all(|c| matches!(c.trigger_reason, TriggerReason::IdleTimeout { .. }));
            if all_idle {
                if let Ok(Some(latest_host_activity)) = self.store.get_host_latest_event_timestamp(&hostname) {
                    let host_idle_secs = now
                        .signed_duration_since(latest_host_activity)
                        .num_seconds()
                        .max(0) as u64;

                    let min_threshold = candidates
                        .iter()
                        .map(|c| match c.eval.session_type {
                            crate::trigger::SessionType::AiSession(_) => self.trigger_config.ai_idle_secs,
                            crate::trigger::SessionType::ShellSession => self.trigger_config.shell_idle_secs,
                        })
                        .min()
                        .unwrap_or(self.trigger_config.shell_idle_secs);

                    if host_idle_secs < min_threshold {
                        info!(
                            "Suppressing IdleTimeout for host {} ({} sessions): host has active operations (idle {}s < threshold {}s)",
                            hostname,
                            candidates.len(),
                            host_idle_secs,
                            min_threshold
                        );
                        continue;
                    }
                }
            }

            // Check B: Host-Level Periodic Cooldown
            // For continuous active work rollups, enforce minimum interval between routine notifications
            let is_periodic = candidates.iter().any(|c| matches!(c.trigger_reason, TriggerReason::PeriodicRollup { .. }));
            if is_periodic {
                let host_cooldown_secs = self.trigger_config.periodic_rollup_secs;
                if let Ok(Some(last_routine_notify_ts)) = self.store.get_host_last_routine_notification_timestamp(&hostname) {
                    let elapsed_since_host_notify = now
                        .signed_duration_since(last_routine_notify_ts)
                        .num_seconds()
                        .max(0) as u64;

                    if elapsed_since_host_notify < host_cooldown_secs {
                        info!(
                            "Host {} periodic rollup cooldown active ({}s < {}s since last routine notification). Postponing routine dispatch.",
                            hostname, elapsed_since_host_notify, host_cooldown_secs
                        );
                        continue;
                    }
                }
            }

            // Filter out candidates with 0 activities (empty sessions)
            let mut active_candidates = Vec::new();
            for c in candidates {
                if c.report.key_activities.is_empty() {
                    info!(
                        "Silently checkpointing empty session {} on {}",
                        c.summary.session_id, hostname
                    );
                    if !self.dry_run {
                        let _ = self.store.record_notification(
                            c.summary.session_id,
                            c.eval.latest_seq,
                            &c.trigger_reason.display_text(),
                            c.eval.session_type.display_name(),
                            "",
                        );
                    }
                } else {
                    active_candidates.push(c);
                }
            }

            if active_candidates.is_empty() {
                continue;
            }

            // Consolidate active candidates for this host into ONE unified report
            let (final_report, sessions_to_checkpoint) = if active_candidates.len() == 1 {
                let c = active_candidates.remove(0);
                let preview = c.report.key_activities.join("; ");
                (
                    c.report,
                    vec![(
                        c.summary.session_id,
                        c.eval.latest_seq,
                        c.eval.session_type.display_name().to_string(),
                        preview,
                        c.trigger_reason.display_text(),
                    )],
                )
            } else {
                let primary = &active_candidates[0];
                let mut all_activities = Vec::new();
                let mut min_start = primary.report.start_time;
                let mut max_end = primary.report.end_time;
                let mut total_bytes = 0;
                let mut has_ai = false;
                let mut sessions_info = Vec::new();

                for c in &active_candidates {
                    if c.report.start_time < min_start {
                        min_start = c.report.start_time;
                    }
                    if c.report.end_time > max_end {
                        max_end = c.report.end_time;
                    }
                    total_bytes += c.report.total_input_bytes;
                    if c.eval.session_type.is_ai() {
                        has_ai = true;
                    }

                    for act in &c.report.key_activities {
                        if !all_activities.contains(act) {
                            all_activities.push(act.clone());
                        }
                    }

                    let preview = c.report.key_activities.join("; ");
                    sessions_info.push((
                        c.summary.session_id,
                        c.eval.latest_seq,
                        c.eval.session_type.display_name().to_string(),
                        preview,
                        c.trigger_reason.display_text(),
                    ));
                }

                let session_type = if has_ai {
                    crate::trigger::SessionType::AiSession("Claude Code / Agent (다중 세션 통합)".to_string())
                } else {
                    crate::trigger::SessionType::ShellSession
                };

                let duration_secs = max_end
                    .signed_duration_since(min_start)
                    .num_seconds()
                    .max(1) as u64;

                let trigger_reason = primary.trigger_reason.clone();

                let agg_report = NotificationReport {
                    session_id: primary.summary.session_id,
                    hostname: hostname.clone(),
                    username: primary.report.username.clone(),
                    client_ip: primary.report.client_ip.clone(),
                    ssh_key_fingerprint: primary.report.ssh_key_fingerprint.clone(),
                    ssh_key_comment: primary.report.ssh_key_comment.clone(),
                    session_type,
                    trigger_reason,
                    start_time: min_start,
                    end_time: max_end,
                    duration_secs,
                    key_activities: all_activities,
                    alert_count: 0,
                    alerts: Vec::new(),
                    is_tampered: false,
                    total_input_bytes: total_bytes,
                };

                (agg_report, sessions_info)
            };

            // Dispatch and checkpoint
            if !self.dry_run {
                let summary_preview = final_report.key_activities.join("; ");
                let is_duplicate = {
                    let mut map = self.recent_dispatches.lock().unwrap();
                    let key = (final_report.hostname.clone(), summary_preview.clone());
                    let now_inst = std::time::Instant::now();
                    if map.len() > 500 {
                        map.retain(|_, v| now_inst.duration_since(*v) < Duration::from_secs(600));
                    }
                    if let Some(&last_sent) = map.get(&key) {
                        if now_inst.duration_since(last_sent) < Duration::from_secs(180) {
                            true
                        } else {
                            map.insert(key, now_inst);
                            false
                        }
                    } else {
                        map.insert(key, now_inst);
                        false
                    }
                };

                if is_duplicate {
                    info!("Skipping duplicate consolidated notification for host {}", hostname);
                } else if let Err(e) = TelegramNotifier::send_report(&self.telegram_config, &final_report).await {
                    error!(
                        "Failed to dispatch consolidated Telegram notification for host {}: {e}. Retaining checkpoints for retry.",
                        hostname
                    );
                } else {
                    info!(
                        "Successfully dispatched consolidated notification for host {} ({} sessions included)",
                        hostname,
                        sessions_to_checkpoint.len()
                    );
                    for (sid, seq, stype, preview, reason_text) in sessions_to_checkpoint {
                        if let Err(e) = self.store.record_notification(sid, seq, &reason_text, &stype, &preview) {
                            error!("Failed to record notification checkpoint for session {}: {e}", sid);
                        }
                    }
                }
            } else {
                info!(
                    "[DRY-RUN] Consolidated notification for host {} ({} sessions included)",
                    hostname,
                    sessions_to_checkpoint.len()
                );
            }

            dispatched_reports.push(final_report);
        }

        Ok(dispatched_reports)
    }

    /// Run continuous background polling daemon
    pub async fn run_daemon(
        &self,
        poll_interval: Duration,
        mut shutdown_rx: Option<tokio::sync::broadcast::Receiver<()>>,
    ) -> Result<()> {
        info!(
            "Starting Argus AI-Aware Session Watcher daemon (Polling interval: {:?}, Dry-run: {})",
            poll_interval, self.dry_run
        );

        let mut ticker = tokio::time::interval(poll_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.check_all_sessions().await {
                        error!("Error during session watcher check cycle: {e}");
                    }
                }
                _ = async {
                    if let Some(ref mut rx) = shutdown_rx {
                        let _ = rx.recv().await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                } => {
                    info!("Session Watcher received shutdown signal. Exiting loop.");
                    break;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::events::{KeystrokeInput, SessionInit};
    use chrono::Duration as ChronoDuration;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_session_watcher_flow_and_checkpointing() {
        let store = AuditStore::new_in_memory().unwrap();
        let sid = Uuid::new_v4();
        let start = Utc::now() - ChronoDuration::minutes(10);

        let init = AuditEvent::SessionInit(SessionInit {
            session_id: sid,
            timestamp: start,
            hostname: "test-host".into(),
            username: "dev".into(),
            tty: "pts/1".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(12345),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });

        let key = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"git status\ncargo check\n".to_vec(), true)
                .with_timestamp(start),
        );

        store.insert_batch(&[init, key]).unwrap();

        let trigger_config = TriggerConfig::from_mins(3, 15);
        let telegram_config = TelegramConfig {
            bot_token: None, // dry run / no dispatch
            chat_id: Some("123".into()),
            thread_id: None,
            server_name: Some("test-host".into()),
        };

        let watcher = SessionWatcher::new(store.clone(), trigger_config, telegram_config, false);

        // 1. First check: session has been idle for 10m (threshold 3m) -> triggers 1 report
        let reports = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].session_id, sid);
        assert!(reports[0]
            .key_activities
            .contains(&"`git status`".to_string()));

        // Checkpoint should now be recorded in DB
        let last_seq = store.get_last_notified_seq(sid).unwrap();
        assert!(last_seq > 0);

        // 2. Second check without new events: should NOT trigger again (deduplicated / roll-up)
        let reports_2 = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports_2.len(), 0);
    }

    #[tokio::test]
    async fn test_host_idle_suppressed_when_another_session_is_active() {
        let store = AuditStore::new_in_memory().unwrap();
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();
        let old_time = Utc::now() - ChronoDuration::minutes(10);
        let recent_time = Utc::now() - ChronoDuration::minutes(1);

        // Session 1: idle for 10 minutes on "martian2"
        let init1 = AuditEvent::SessionInit(SessionInit {
            session_id: sid1,
            timestamp: old_time,
            hostname: "martian2".into(),
            username: "root".into(),
            tty: "pts/1".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(12345),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        let key1 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid1, 1, 100, b"tmux a -t ep-tm\n".to_vec(), true)
                .with_timestamp(old_time),
        );

        // Session 2: active 1 minute ago on "martian2"
        let init2 = AuditEvent::SessionInit(SessionInit {
            session_id: sid2,
            timestamp: recent_time,
            hostname: "martian2".into(),
            username: "root".into(),
            tty: "pts/2".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(12346),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        let key2 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid2, 1, 100, b"tmux a -t sho\n".to_vec(), true)
                .with_timestamp(recent_time),
        );

        store.insert_batch(&[init1, key1, init2, key2]).unwrap();

        let trigger_config = TriggerConfig::from_mins(3, 15);
        let telegram_config = TelegramConfig {
            bot_token: None,
            chat_id: Some("123".into()),
            thread_id: None,
            server_name: Some("martian2".into()),
        };

        let watcher = SessionWatcher::new(store.clone(), trigger_config, telegram_config, false);

        // Session 1 alone is > 3m idle, but host's latest activity was 1m ago (< 3m)
        // Therefore, IdleTimeout must be suppressed!
        let reports = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports.len(), 0, "IdleTimeout should be suppressed while host is active in another session");
    }

    #[tokio::test]
    async fn test_multi_session_consolidation_into_single_report() {
        let store = AuditStore::new_in_memory().unwrap();
        let sid1 = Uuid::new_v4();
        let sid2 = Uuid::new_v4();
        let time1 = Utc::now() - ChronoDuration::minutes(15);
        let time2 = Utc::now() - ChronoDuration::minutes(10);

        let init1 = AuditEvent::SessionInit(SessionInit {
            session_id: sid1,
            timestamp: time1,
            hostname: "martian2".into(),
            username: "root".into(),
            tty: "pts/1".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(12345),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        let key1 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid1, 1, 100, b"git status\n".to_vec(), true)
                .with_timestamp(time1),
        );

        let init2 = AuditEvent::SessionInit(SessionInit {
            session_id: sid2,
            timestamp: time2,
            hostname: "martian2".into(),
            username: "root".into(),
            tty: "pts/2".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(12346),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        let key2 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid2, 1, 100, b"cargo check\n".to_vec(), true)
                .with_timestamp(time2),
        );

        store.insert_batch(&[init1, key1, init2, key2]).unwrap();

        let trigger_config = TriggerConfig::from_mins(3, 15);
        let telegram_config = TelegramConfig {
            bot_token: None,
            chat_id: Some("123".into()),
            thread_id: None,
            server_name: Some("martian2".into()),
        };

        let watcher = SessionWatcher::new(store.clone(), trigger_config, telegram_config, false);

        // Both sessions have been idle for > 3m (10m and 15m ago).
        // They should be consolidated into EXACTLY 1 report for martian2!
        let reports = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports.len(), 1, "Multiple sessions on same host should be consolidated into 1 report");
        assert_eq!(reports[0].hostname, "martian2");
        assert!(reports[0].key_activities.contains(&"`git status`".to_string()));
        assert!(reports[0].key_activities.contains(&"`cargo check`".to_string()));

        // Both sessions should now have checkpoints recorded
        let seq1 = store.get_last_notified_seq(sid1).unwrap();
        let seq2 = store.get_last_notified_seq(sid2).unwrap();
        assert!(seq1 > 0);
        assert!(seq2 > 0);

        // Next poll should yield 0 reports
        let reports_2 = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports_2.len(), 0);
    }

    #[tokio::test]
    async fn test_security_alert_bypasses_host_consolidation_and_cooldown() {
        let store = AuditStore::new_in_memory().unwrap();
        let sid = Uuid::new_v4();
        let recent_time = Utc::now() - ChronoDuration::seconds(10);

        let init = AuditEvent::SessionInit(SessionInit {
            session_id: sid,
            timestamp: recent_time,
            hostname: "martian2".into(),
            username: "attacker".into(),
            tty: "pts/1".into(),
            client_ip: Some("10.0.0.99".into()),
            client_port: Some(5555),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        // Sudo escalation triggers security alert
        let key = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"sudo -i\n".to_vec(), true)
                .with_timestamp(recent_time),
        );

        store.insert_batch(&[init, key]).unwrap();

        let trigger_config = TriggerConfig::from_mins(60, 60);
        let telegram_config = TelegramConfig {
            bot_token: None,
            chat_id: Some("123".into()),
            thread_id: None,
            server_name: Some("martian2".into()),
        };

        let watcher = SessionWatcher::new(store.clone(), trigger_config, telegram_config, false);

        // Security alert must trigger immediately despite 60m idle/rollup configuration
        let reports = watcher.check_all_sessions().await.unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].alert_count > 0 || matches!(reports[0].trigger_reason, TriggerReason::SecurityAnomaly { .. }));
    }
}
