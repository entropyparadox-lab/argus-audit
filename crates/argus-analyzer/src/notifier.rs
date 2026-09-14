use crate::operator::OperatorRegistry;
use crate::reconstructor::ReconstructedActivity;
use crate::rules::RuleEngine;
use crate::trigger::{SessionType, TriggerReason};
use argus_common::events::{AuditEvent, SessionInit};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: Option<String>,
    pub chat_id: Option<String>,
    pub thread_id: Option<i64>,
    pub server_name: Option<String>,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl TelegramConfig {
    pub fn from_env() -> Self {
        let bot_token = env::var("ARGUS_TELEGRAM_BOT_TOKEN")
            .or_else(|_| env::var("TELEGRAM_BOT_TOKEN"))
            .ok()
            .filter(|s| !s.trim().is_empty());

        let chat_id = env::var("ARGUS_TELEGRAM_CHAT_ID")
            .or_else(|_| env::var("TELEGRAM_CHAT_ID"))
            .ok()
            .filter(|s| !s.trim().is_empty());

        let thread_id = env::var("ARGUS_TELEGRAM_THREAD_ID")
            .or_else(|_| env::var("TELEGRAM_THREAD_ID"))
            .ok()
            .and_then(|s| s.parse::<i64>().ok());

        let server_name = env::var("ARGUS_SERVER_NAME")
            .or_else(|_| env::var("HOSTNAME"))
            .ok();

        Self {
            bot_token,
            chat_id,
            thread_id,
            server_name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationReport {
    pub session_id: Uuid,
    pub hostname: String,
    pub username: String,
    pub client_ip: String,
    pub ssh_key_fingerprint: Option<String>,
    pub ssh_key_comment: Option<String>,
    pub session_type: SessionType,
    pub trigger_reason: TriggerReason,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: u64,
    pub key_activities: Vec<String>,
    pub alert_count: usize,
    pub alerts: Vec<String>,
    pub is_tampered: bool,
    pub total_input_bytes: usize,
}

impl NotificationReport {
    /// Build a NotificationReport from session metadata and reconstructed activities
    pub fn build(
        session_id: Uuid,
        identity: Option<&SessionInit>,
        session_type: SessionType,
        trigger_reason: TriggerReason,
        activities: &[ReconstructedActivity],
        events: &[AuditEvent],
        is_tampered: bool,
    ) -> Self {
        let hostname = identity
            .map(|i| i.hostname.clone())
            .unwrap_or_else(|| "unknown-host".to_string());
        let username = identity
            .map(|i| i.username.clone())
            .unwrap_or_else(|| "unknown-user".to_string());
        let client_ip = identity
            .and_then(|i| i.client_ip.clone())
            .unwrap_or_else(|| "local".to_string());
        let ssh_key_fingerprint = identity.and_then(|i| i.ssh_key_fingerprint.clone());
        let ssh_key_comment = identity.and_then(|i| i.ssh_key_comment.clone());

        let start_time = activities
            .first()
            .map(|a| a.timestamp)
            .or_else(|| events.first().map(|e| e.timestamp()))
            .unwrap_or_else(Utc::now);

        let end_time = activities
            .last()
            .map(|a| a.timestamp)
            .or_else(|| events.last().map(|e| e.timestamp()))
            .unwrap_or_else(Utc::now);

        let duration_secs = end_time
            .signed_duration_since(start_time)
            .num_seconds()
            .max(1) as u64;

        let total_input_bytes = events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::KeystrokeInput(k) => Some(k.byte_len),
                _ => None,
            })
            .sum();

        // Collect security alerts
        let mut alerts = Vec::new();
        for event in events {
            let event_alerts = RuleEngine::inspect_event(event);
            for a in event_alerts {
                alerts.push(format!("[{:?}] {}", a.severity, a.description));
            }
        }
        let alert_count = alerts.len();

        // Extract top concise key activities (up to 10 deduplicated commands)
        let mut key_activities = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut total_unique = 0;

        for act in activities {
            let item = act.content.trim();
            if !item.is_empty() && !seen.contains(item) {
                seen.insert(item.to_string());
                total_unique += 1;

                if key_activities.len() < 10 {
                    let short_cmd = if item.chars().count() > 100 {
                        let truncated: String = item.chars().take(100).collect();
                        format!("{truncated}...")
                    } else {
                        item.to_string()
                    };

                    let safe_cmd = short_cmd.replace('`', "'");

                    if act.is_ai {
                        key_activities.push(format!("🤖 Claude Code: \"{}\"", safe_cmd));
                    } else {
                        key_activities.push(format!("`{}`", safe_cmd));
                    }
                }
            }
        }

        if total_unique > 10 {
            key_activities.push(format!("_(외 {}개 작업 생략)_", total_unique - 10));
        }

        Self {
            session_id,
            hostname,
            username,
            client_ip,
            ssh_key_fingerprint,
            ssh_key_comment,
            session_type,
            trigger_reason,
            start_time,
            end_time,
            duration_secs,
            key_activities,
            alert_count,
            alerts,
            is_tampered,
            total_input_bytes,
        }
    }

    /// Format report into crisp, executive-grade Telegram Markdown
    pub fn format_telegram_markdown(&self) -> String {
        let dur_mins = (self.duration_secs + 59) / 60;
        let kst = chrono::FixedOffset::east_opt(9 * 3600).unwrap();
        let start_kst = self.start_time.with_timezone(&kst);
        let end_kst = self.end_time.with_timezone(&kst);
        let start_str = start_kst.format("%H:%M").to_string();
        let end_str = if start_kst.date_naive() != end_kst.date_naive() {
            end_kst.format("%m/%d %H:%M").to_string()
        } else {
            end_kst.format("%H:%M").to_string()
        };

        let mut lines = Vec::new();
        let is_security = self.alert_count > 0
            || self.is_tampered
            || matches!(self.trigger_reason, TriggerReason::SecurityAnomaly { .. });

        if is_security {
            lines.push("🚨 *[Argus Audit] 긴급 보안 이상 경보*".to_string());
        } else if matches!(self.trigger_reason, TriggerReason::PeriodicRollup { .. }) {
            lines.push("⏱️ *[Argus Audit] 정기 작업 진행 요약 (1시간)*".to_string());
        } else {
            lines.push("🛡️ *[Argus Audit] 작업 완료 알림*".to_string());
        }
        lines.push("".to_string());

        let operator_name = OperatorRegistry::resolve_operator_name(
            &self.username,
            self.ssh_key_comment.as_deref(),
            self.ssh_key_fingerprint.as_deref(),
        );

        let ssh_meta = match (
            operator_name,
            &self.ssh_key_comment,
            &self.ssh_key_fingerprint,
        ) {
            (Some(name), Some(comment), _) => {
                format!(
                    "• *작업자:* `{}` ({} <`{}`> / IP: `{}`)",
                    self.username, name, comment, self.client_ip
                )
            }
            (Some(name), None, Some(fp)) => {
                format!(
                    "• *작업자:* `{}` ({} <`{}`> / IP: `{}`)",
                    self.username, name, fp, self.client_ip
                )
            }
            (Some(name), None, None) => {
                format!(
                    "• *작업자:* `{}` ({} / IP: `{}`)",
                    self.username, name, self.client_ip
                )
            }
            (None, Some(comment), _) => {
                format!(
                    "• *작업자:* `{}` (`{}` / IP: `{}`)",
                    self.username, comment, self.client_ip
                )
            }
            (None, None, Some(fp)) => {
                format!(
                    "• *작업자:* `{}` (`{}` / IP: `{}`)",
                    self.username, fp, self.client_ip
                )
            }
            (None, None, None) => {
                format!("• *작업자:* `{}` (IP: `{}`)", self.username, self.client_ip)
            }
        };

        lines.push(format!("• *서버:* `{}`", self.hostname));
        lines.push(ssh_meta);
        if self
            .alerts
            .iter()
            .any(|a| a.contains("root shell escalation") || a.contains("Root shell escalation"))
        {
            lines.push("• *보안 상태:* ⚡ `root 권한 상승 이력 있음 (sudo -i / su)`".to_string());
        }
        lines.push(format!(
            "• *세션 유형:* {}",
            self.session_type.display_name()
        ));
        lines.push(format!(
            "• *트리거:* {}",
            self.trigger_reason.display_text()
        ));
        lines.push(format!(
            "• *작업 구간:* `{} ~ {} (KST)` (약 {}분 작업)",
            start_str, end_str, dur_mins
        ));
        lines.push("".to_string());

        if is_security {
            lines.push("🔒 *보안 이상 점검 결과:*".to_string());
            if self.is_tampered {
                lines.push("  • ❌ *위변조 의심 / 해시 체인 불일치*".to_string());
            }
            if self.alert_count > 0 {
                lines.push(format!("  • ⚠️ *이상 경보 ({}건)*:", self.alert_count));
                for a in &self.alerts {
                    lines.push(format!("      - {}", a));
                }
            }
            lines.push("".to_string());
        }

        lines.push("📋 *수행한 주요 작업 내역:*".to_string());
        if self.key_activities.is_empty() {
            lines.push("  _(수행된 명령어 없음)_".to_string());
        } else {
            for (idx, act) in self.key_activities.iter().enumerate() {
                if act.starts_with("_(") {
                    lines.push(format!("  {}", act));
                } else {
                    lines.push(format!("  {}. {}", idx + 1, act));
                }
            }
        }
        lines.push("".to_string());

        if !is_security {
            lines.push("🔒 *보안 및 무결성 점검:*".to_string());
            lines.push("  • 이상 경보: `0건 (정상/안전)`".to_string());
            let tamper_status = if self.is_tampered {
                "❌ *위변조 의심 / 해시 체인 불일치*"
            } else {
                "✅ *해시 체인 검증 완료 (SHA256)*"
            };
            lines.push(format!("  • 로그 무결성: {}", tamper_status));
        }

        let mut text = lines.join("\n");
        // Defensive safeguard against Telegram 4096 character limit
        if text.chars().count() > 3900 {
            let truncated: String = text.chars().take(3850).collect();
            text = format!("{truncated}\n\n...(메시지 길이 제한으로 일부 내용 생략)");
        }
        text
    }
}

pub struct TelegramNotifier;

impl TelegramNotifier {
    /// Send report to Telegram API
    pub async fn send_report(
        config: &TelegramConfig,
        report: &NotificationReport,
    ) -> Result<(), String> {
        // Defensive check: Do not dispatch empty notifications if there are no activities, no alerts, and no tampering
        if report.key_activities.is_empty() && report.alert_count == 0 && !report.is_tampered {
            return Ok(());
        }

        let bot_token = match &config.bot_token {
            Some(t) if !t.is_empty() => t,
            _ => {
                // Token not configured: gracefully return ok
                return Ok(());
            }
        };

        let chat_id = match &config.chat_id {
            Some(c) if !c.is_empty() => c,
            _ => return Err("Telegram Chat ID not configured".to_string()),
        };

        let markdown_text = report.format_telegram_markdown();
        let client = Client::new();

        let mut payload = json!({
            "chat_id": chat_id,
            "text": markdown_text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": true
        });

        if let Some(thread_id) = config.thread_id {
            payload["message_thread_id"] = json!(thread_id);
        }

        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send Telegram message: {e}"))?;

        if !resp.status().is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            // Markdown parsing fallback: if Telegram rejected markdown entity parsing (e.g. unescaped bash chars), retry as plain text
            if err_body.contains("can't parse") || err_body.contains("parse entities") {
                tracing::warn!(
                    "Telegram markdown entity parse failed, falling back to plain text dispatch: {err_body}"
                );
                if let Some(obj) = payload.as_object_mut() {
                    obj.remove("parse_mode");
                }
                let retry_resp = client
                    .post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| format!("Failed to send fallback plain text message: {e}"))?;
                if !retry_resp.status().is_success() {
                    let retry_err = retry_resp.text().await.unwrap_or_default();
                    return Err(format!("Telegram API error (fallback): {retry_err}"));
                }
                return Ok(());
            }
            return Err(format!("Telegram API error: {err_body}"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconstructor::ActivityKind;

    #[test]
    fn test_format_telegram_markdown() {
        let sid = Uuid::new_v4();
        let init = SessionInit {
            session_id: sid,
            timestamp: Utc::now(),
            hostname: "prod-server-01".into(),
            username: "alice".into(),
            tty: "ttys002".into(),
            client_ip: Some("198.51.100.42".into()),
            client_port: Some(52341),
            ssh_key_fingerprint: Some("SHA256:abcd".into()),
            ssh_key_comment: Some("alice@workstation".into()),
            env_context: None,
        };

        let activities = vec![
            ReconstructedActivity {
                timestamp: Utc::now(),
                content: "git checkout -b feat/ai-trigger".into(),
                kind: ActivityKind::Command,
                is_ai: false,
            },
            ReconstructedActivity {
                timestamp: Utc::now(),
                content: "Refactor dynamic idle timeout in Rust".into(),
                kind: ActivityKind::AiPrompt,
                is_ai: true,
            },
            ReconstructedActivity {
                timestamp: Utc::now(),
                content: "cargo test".into(),
                kind: ActivityKind::Command,
                is_ai: false,
            },
        ];

        let report = NotificationReport::build(
            sid,
            Some(&init),
            SessionType::AiSession("🤖 AI 페어링 세션 (Claude Code)".into()),
            TriggerReason::IdleTimeout {
                idle_secs: 900,
                threshold_secs: 900,
            },
            &activities,
            &[],
            false,
        );

        let md = report.format_telegram_markdown();
        assert!(md.contains("🛡️ *[Argus Audit] 작업 완료 알림*"));
        assert!(md.contains("prod-server-01"));
        assert!(md.contains("alice"));
        assert!(md.contains("198.51.100.42"));
        assert!(md.contains("⏱️ 유휴 감지"));
        assert!(md.contains("🤖 Claude Code: \"Refactor dynamic idle timeout in Rust\""));
        assert!(md.contains("`git checkout -b feat/ai-trigger`"));
        assert!(md.contains("`cargo test`"));
        assert!(md.contains("✅ *해시 체인 검증 완료 (SHA256)*"));
        assert!(md.contains("(KST)"));
    }

    #[test]
    fn test_format_telegram_markdown_security_alert() {
        let sid = Uuid::new_v4();
        let init = SessionInit {
            session_id: sid,
            timestamp: Utc::now(),
            hostname: "prod-server-01".into(),
            username: "hacker".into(),
            tty: "ttys002".into(),
            client_ip: Some("203.0.113.5".into()),
            client_port: Some(44221),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        };

        let activities = vec![ReconstructedActivity {
            timestamp: Utc::now(),
            content: "sudo -i".into(),
            kind: ActivityKind::Command,
            is_ai: false,
        }];

        let sudo_event = AuditEvent::KeystrokeInput(
            argus_common::events::KeystrokeInput::new(
                sid,
                1,
                100,
                b"sudo -i\n".to_vec(),
                true,
            ),
        );

        let report = NotificationReport::build(
            sid,
            Some(&init),
            SessionType::ShellSession,
            TriggerReason::SecurityAnomaly {
                alert_count: 1,
                max_severity: "High".into(),
            },
            &activities,
            &[sudo_event],
            false,
        );

        let md = report.format_telegram_markdown();
        assert!(md.contains("🚨 *[Argus Audit] 긴급 보안 이상 경보*"));
        assert!(md.contains("⚠️ *이상 경보 (1건)*"));
        assert!(md.contains("root shell escalation"));
        assert!(md.contains("`sudo -i`"));
    }

    #[test]
    fn test_format_telegram_markdown_truncates_oversized_messages() {
        let sid = Uuid::new_v4();
        let init = SessionInit {
            session_id: sid,
            timestamp: Utc::now(),
            hostname: "prod-server-01".into(),
            username: "heavy-user".into(),
            tty: "ttys003".into(),
            client_ip: Some("127.0.0.1".into()),
            client_port: Some(22),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        };

        // Create 50 long activities
        let activities: Vec<_> = (0..50)
            .map(|i| ReconstructedActivity {
                timestamp: Utc::now(),
                content: format!("echo 'very long string repeated {} times: {}'", i, "a".repeat(200)),
                kind: ActivityKind::Command,
                is_ai: false,
            })
            .collect();

        let report = NotificationReport::build(
            sid,
            Some(&init),
            SessionType::ShellSession,
            TriggerReason::PeriodicRollup { elapsed_mins: 60 },
            &activities,
            &[],
            false,
        );

        let md = report.format_telegram_markdown();
        assert!(md.chars().count() <= 3950);
        assert!(md.contains("⏱️ *[Argus Audit] 정기 작업 진행 요약 (1시간)*"));
    }
}
