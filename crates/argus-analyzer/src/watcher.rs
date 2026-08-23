use crate::notifier::{NotificationReport, TelegramConfig, TelegramNotifier};
use crate::trigger::{AiAwareTriggerEvaluator, TriggerConfig};
use anyhow::Result;
use argus_collector::AuditStore;
use argus_common::events::AuditEvent;
use chrono::Utc;
use std::time::Duration;
use tracing::{error, info, warn};

pub struct SessionWatcher {
    store: AuditStore,
    trigger_config: TriggerConfig,
    telegram_config: TelegramConfig,
    dry_run: bool,
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
        }
    }

    /// Run one round of trigger evaluations against all recent active sessions
    pub async fn check_all_sessions(&self) -> Result<Vec<NotificationReport>> {
        let sessions = self.store.list_sessions(100)?;
        let mut dispatched_reports = Vec::new();
        let now = Utc::now();

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

            if eval.should_notify {
                let trigger_reason = eval.trigger_reason.clone().unwrap();
                let is_tampered = self.store.verify_session_integrity(s.session_id).is_err();

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

                if !self.dry_run {
                    // Send to Telegram
                    if let Err(e) =
                        TelegramNotifier::send_report(&self.telegram_config, &report).await
                    {
                        error!(
                            "Failed to dispatch Telegram notification for session {}: {e}",
                            s.session_id
                        );
                    } else {
                        info!(
                            "Successfully dispatched session notification for {} (Trigger: {})",
                            s.session_id,
                            trigger_reason.display_text()
                        );
                    }

                    // Record checkpoint in SQLite
                    let summary_preview = report.key_activities.join("; ");
                    if let Err(e) = self.store.record_notification(
                        s.session_id,
                        eval.latest_seq,
                        &trigger_reason.display_text(),
                        eval.session_type.display_name(),
                        &summary_preview,
                    ) {
                        error!(
                            "Failed to record notification checkpoint for session {}: {e}",
                            s.session_id
                        );
                    }
                } else {
                    info!(
                        "[DRY-RUN] Triggered notification for {} (Reason: {})",
                        s.session_id,
                        trigger_reason.display_text()
                    );
                }

                dispatched_reports.push(report);
            }
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
}
