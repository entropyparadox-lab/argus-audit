use crate::reconstructor::{KeystrokeReconstructor, ReconstructedSession};
use argus_common::events::{AuditEvent, SessionEnd};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    AiSession(String),
    ShellSession,
}

impl SessionType {
    pub fn display_name(&self) -> &str {
        match self {
            SessionType::AiSession(tool) => tool.as_str(),
            SessionType::ShellSession => "일반 터미널 세션 (Bash/Zsh)",
        }
    }

    pub fn is_ai(&self) -> bool {
        matches!(self, SessionType::AiSession(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggerReason {
    /// Fired when terminal idle duration exceeds dynamic threshold (3m for shell, 15m for AI)
    IdleTimeout { idle_secs: u64, threshold_secs: u64 },
    /// Fired when client disconnects (SSH detached, laptop closed, or TTY closed while background tasks run)
    ClientDisconnect { reason: String },
    /// Fired upon normal shell logout or exit
    SessionExit { exit_status: Option<i32> },
    /// Triggered manually by operator or CLI
    Manual,
}

impl TriggerReason {
    pub fn display_text(&self) -> String {
        match self {
            TriggerReason::IdleTimeout {
                idle_secs,
                threshold_secs,
            } => {
                let mins = threshold_secs / 60;
                let idle_mins = idle_secs / 60;
                if idle_mins > mins {
                    format!("⏱️ 유휴 감지 ({}분 경과 / 임계치 {}분)", idle_mins, mins)
                } else {
                    format!("⏱️ 유휴 감지 ({}분 경과)", mins)
                }
            }
            TriggerReason::ClientDisconnect { reason } => {
                format!("🔌 SSH 연결 단절 / Detach ({})", reason)
            }
            TriggerReason::SessionExit { exit_status } => {
                let code = exit_status
                    .map(|c| format!("코드 {c}"))
                    .unwrap_or_else(|| "0".into());
                format!("🚪 정상 세션 종료 ({})", code)
            }
            TriggerReason::Manual => "✋ 수동 요약 요청".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TriggerConfig {
    /// Idle timeout for regular terminal sessions (default: 3 minutes = 180s)
    pub shell_idle_secs: u64,
    /// Dynamic expanded idle timeout for AI / Claude sessions (default: 15 minutes = 900s)
    pub ai_idle_secs: u64,
    /// Minimum unnotified input bytes before triggering
    pub min_input_bytes: usize,
    /// Minimum command count
    pub min_commands: usize,
    /// Minimum duration in seconds
    pub min_duration_secs: u64,
    /// Trivial single-ping commands to suppress
    pub trivial_commands: Vec<String>,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            shell_idle_secs: 180, // 3 minutes
            ai_idle_secs: 900,    // 15 minutes
            min_input_bytes: 3,
            min_commands: 1,
            min_duration_secs: 2,
            trivial_commands: vec![
                "exit".into(),
                "logout".into(),
                "clear".into(),
                "cls".into(),
                "w".into(),
                "whoami".into(),
                "uptime".into(),
            ],
        }
    }
}

impl TriggerConfig {
    pub fn from_mins(shell_idle_mins: u64, ai_idle_mins: u64) -> Self {
        Self {
            shell_idle_secs: shell_idle_mins * 60,
            ai_idle_secs: ai_idle_mins * 60,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct TriggerEvaluation {
    pub session_id: Uuid,
    pub should_notify: bool,
    pub trigger_reason: Option<TriggerReason>,
    pub session_type: SessionType,
    pub is_noise: bool,
    pub noise_reason: Option<String>,
    pub unnotified_reconstructed: ReconstructedSession,
    pub unnotified_events: Vec<AuditEvent>,
    pub latest_seq: u64,
    pub last_activity_timestamp: Option<DateTime<Utc>>,
    pub idle_secs: u64,
}

pub struct AiAwareTriggerEvaluator;

impl AiAwareTriggerEvaluator {
    /// Evaluate a session's event history and determine if any of the 3 smart triggers are tripped
    pub fn evaluate(
        session_id: Uuid,
        session_created_at: DateTime<Utc>,
        all_events: &[AuditEvent],
        last_notified_seq: u64,
        now: DateTime<Utc>,
        config: &TriggerConfig,
    ) -> TriggerEvaluation {
        // 1. Separate events since last notification checkpoint
        let mut unnotified_events = Vec::new();
        let mut latest_seq = last_notified_seq;
        let mut session_end_event: Option<SessionEnd> = None;
        let mut global_has_ai = false;

        for (idx, event) in all_events.iter().enumerate() {
            let seq = (idx + 1) as u64;
            if seq > latest_seq {
                latest_seq = seq;
            }

            // Detect global AI involvement across entire session history
            match event {
                AuditEvent::PromptTrace(_) => {
                    global_has_ai = true;
                }
                AuditEvent::ProcessExec(p) => {
                    let cmdline = p.argv.join(" ");
                    if KeystrokeReconstructor::is_ai_tool_invocation(&cmdline)
                        || KeystrokeReconstructor::is_ai_tool_invocation(&p.comm)
                    {
                        global_has_ai = true;
                    }
                }
                AuditEvent::SessionEnd(end) => {
                    session_end_event = Some(end.clone());
                }
                _ => {}
            }

            if seq > last_notified_seq {
                unnotified_events.push(event.clone());
            }
        }

        // Reconstruct unnotified activity
        let unnotified_session = KeystrokeReconstructor::reconstruct(&unnotified_events);
        if unnotified_session.has_ai_activity {
            global_has_ai = true;
        }

        let session_type = if global_has_ai {
            SessionType::AiSession("🤖 AI 페어링 세션 (Claude Code / AI CLI)".to_string())
        } else {
            SessionType::ShellSession
        };

        // Determine last activity timestamp
        let last_activity = unnotified_session
            .last_activity
            .or_else(|| all_events.last().map(|e| e.timestamp()))
            .unwrap_or(session_created_at);

        let idle_secs = now
            .signed_duration_since(last_activity)
            .num_seconds()
            .max(0) as u64;

        // 2. Noise Filtering Check
        let (is_noise, noise_reason) =
            Self::check_noise(&unnotified_session, &unnotified_events, config);

        if is_noise || unnotified_events.is_empty() {
            return TriggerEvaluation {
                session_id,
                should_notify: false,
                trigger_reason: None,
                session_type,
                is_noise,
                noise_reason,
                unnotified_reconstructed: unnotified_session,
                unnotified_events,
                latest_seq,
                last_activity_timestamp: Some(last_activity),
                idle_secs,
            };
        }

        // 3. Trigger 1 & 2 & 3 Evaluation
        let mut trigger_reason = None;

        // Trigger A: Session Ended / SSH Client Detached
        if let Some(ref end) = session_end_event {
            if session_type.is_ai() {
                trigger_reason = Some(TriggerReason::ClientDisconnect {
                    reason: "SSH 연결 종료 / 세션 Detach".into(),
                });
            } else {
                trigger_reason = Some(TriggerReason::SessionExit {
                    exit_status: end.exit_status,
                });
            }
        } else {
            // Trigger B: Dynamic Idle Timeout (3m Shell vs 15m AI)
            let threshold_secs = if session_type.is_ai() {
                config.ai_idle_secs
            } else {
                config.shell_idle_secs
            };

            if idle_secs >= threshold_secs {
                trigger_reason = Some(TriggerReason::IdleTimeout {
                    idle_secs,
                    threshold_secs,
                });
            }
        }

        let should_notify = trigger_reason.is_some();

        TriggerEvaluation {
            session_id,
            should_notify,
            trigger_reason,
            session_type,
            is_noise: false,
            noise_reason: None,
            unnotified_reconstructed: unnotified_session,
            unnotified_events,
            latest_seq,
            last_activity_timestamp: Some(last_activity),
            idle_secs,
        }
    }

    /// Check if the unnotified batch is trivial noise (e.g. empty, single ping, 0 commands)
    fn check_noise(
        session: &ReconstructedSession,
        events: &[AuditEvent],
        config: &TriggerConfig,
    ) -> (bool, Option<String>) {
        if events.is_empty() {
            return (true, Some("No new events recorded".to_string()));
        }

        // Filter 1: Zero commands and minimal input bytes
        if session.total_commands == 0 && session.total_input_bytes < config.min_input_bytes {
            return (
                true,
                Some(format!(
                    "Trivial empty session ({} bytes, 0 commands)",
                    session.total_input_bytes
                )),
            );
        }

        // Filter 2: Single trivial command (e.g. just `exit`, `uptime`) with short duration
        if session.total_commands == 1 && session.activities.len() == 1 {
            let cmd = session.activities[0].content.to_lowercase();
            let first_token = cmd.split_whitespace().next().unwrap_or("");
            if config.trivial_commands.iter().any(|t| t == first_token) {
                return (
                    true,
                    Some(format!("Suppressed trivial command: \"{}\"", cmd)),
                );
            }
        }

        (false, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::events::KeystrokeInput;
    use chrono::Duration;

    #[test]
    fn test_dynamic_idle_timeout_shell_vs_ai() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::from_mins(3, 15);
        let start = Utc::now() - Duration::minutes(20);

        // 1. Regular shell session: 5 minutes of idle should TRIGGER (threshold is 3m)
        let shell_event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"git status\ncargo build\n".to_vec(), true)
                .with_timestamp(start),
        );

        let now_shell = start + Duration::minutes(5);
        let eval_shell =
            AiAwareTriggerEvaluator::evaluate(sid, start, &[shell_event], 0, now_shell, &config);

        assert!(eval_shell.should_notify);
        assert!(!eval_shell.session_type.is_ai());
        if let Some(TriggerReason::IdleTimeout {
            idle_secs,
            threshold_secs,
        }) = eval_shell.trigger_reason
        {
            assert_eq!(threshold_secs, 180);
            assert!(idle_secs >= 180);
        } else {
            panic!("Expected IdleTimeout trigger for shell");
        }

        // 2. AI Claude session: 5 minutes of idle should NOT TRIGGER (threshold is 15m)
        let ai_event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid,
                1,
                100,
                b"claude 'Refactor payment gateway'\n".to_vec(),
                true,
            )
            .with_timestamp(start),
        );

        let now_ai_5m = start + Duration::minutes(5);
        let eval_ai_5m = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[ai_event.clone()],
            0,
            now_ai_5m,
            &config,
        );

        assert!(
            !eval_ai_5m.should_notify,
            "5m idle should NOT trigger Claude session"
        );
        assert!(eval_ai_5m.session_type.is_ai());

        // 3. AI Claude session: 16 minutes of idle SHOULD TRIGGER (threshold 15m exceeded)
        let now_ai_16m = start + Duration::minutes(16);
        let eval_ai_16m =
            AiAwareTriggerEvaluator::evaluate(sid, start, &[ai_event], 0, now_ai_16m, &config);

        assert!(
            eval_ai_16m.should_notify,
            "16m idle SHOULD trigger Claude session"
        );
        assert!(eval_ai_16m.session_type.is_ai());
    }

    #[test]
    fn test_noise_filter_suppresses_trivial_exit() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default();
        let start = Utc::now();

        let trivial_event =
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 1, 100, b"exit\n".to_vec(), false));

        let end_event = AuditEvent::SessionEnd(SessionEnd {
            session_id: sid,
            timestamp: start + Duration::seconds(2),
            duration_ms: 2000,
            total_input_bytes: 5,
            exit_status: Some(0),
        });

        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[trivial_event, end_event],
            0,
            start + Duration::seconds(5),
            &config,
        );

        assert!(!eval.should_notify);
        assert!(eval.is_noise);
    }
}
