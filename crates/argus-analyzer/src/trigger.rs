use crate::reconstructor::{KeystrokeReconstructor, ReconstructedSession};
use crate::rules::RuleEngine;
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
    /// Fired when terminal idle duration exceeds dynamic threshold (15m for shell, 30m for AI)
    IdleTimeout { idle_secs: u64, threshold_secs: u64 },
    /// Fired when client disconnects (SSH detached, laptop closed, or TTY closed while background tasks run)
    ClientDisconnect { reason: String },
    /// Fired upon normal shell logout or exit
    SessionExit { exit_status: Option<i32> },
    /// Triggered manually by operator or CLI
    Manual,
    /// Periodic rollup fired for continuous ongoing work (e.g. 1 hour = 60m)
    PeriodicRollup { elapsed_mins: u64 },
    /// Fired immediately upon detection of security anomalies or suspicious behavior
    SecurityAnomaly {
        alert_count: usize,
        max_severity: String,
    },
}

impl TriggerReason {
    pub fn display_text(&self) -> String {
        match self {
            TriggerReason::PeriodicRollup { elapsed_mins } => {
                format!("⏱️ 정기 작업 요약 (약 {}분 연속 작업 진행 중)", elapsed_mins)
            }
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
            TriggerReason::SecurityAnomaly {
                alert_count,
                max_severity,
            } => {
                format!("🚨 긴급 보안 이상 감지 ({}건 / {})", alert_count, max_severity)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TriggerConfig {
    /// Idle timeout for regular terminal sessions (default: 60 minutes = 3600s)
    pub shell_idle_secs: u64,
    /// Dynamic expanded idle timeout for AI / Claude sessions (default: 60 minutes = 3600s)
    pub ai_idle_secs: u64,
    /// Periodic continuous active work rollup interval (default: 60 minutes = 3600s)
    pub periodic_rollup_secs: u64,
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
            shell_idle_secs: 3600, // 60 minutes
            ai_idle_secs: 3600,    // 60 minutes
            periodic_rollup_secs: 3600, // 60 minutes
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
                "pwd".into(),
                "history".into(),
            ],
        }
    }
}

impl TriggerConfig {
    pub fn from_mins(shell_idle_mins: u64, ai_idle_mins: u64) -> Self {
        Self {
            shell_idle_secs: shell_idle_mins * 60,
            ai_idle_secs: ai_idle_mins * 60,
            periodic_rollup_secs: 3600,
            ..Default::default()
        }
    }

    pub fn from_mins_with_rollup(
        shell_idle_mins: u64,
        ai_idle_mins: u64,
        periodic_rollup_mins: u64,
    ) -> Self {
        Self {
            shell_idle_secs: shell_idle_mins * 60,
            ai_idle_secs: ai_idle_mins * 60,
            periodic_rollup_secs: periodic_rollup_mins * 60,
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

        // 3. Trigger 0 (Security), 1 (End/Detach), 2 (Idle Timeout)
        let mut trigger_reason = None;

        // Trigger 0: IMMEDIATE Security Alert (Priority 1)
        // If unnotified events contain any security anomalies (Critical, High, Medium), trigger immediately!
        let security_alerts: Vec<_> = unnotified_events
            .iter()
            .flat_map(RuleEngine::inspect_event)
            .collect();

        if !security_alerts.is_empty() {
            let alert_count = security_alerts.len();
            let max_sev = security_alerts
                .iter()
                .map(|a| a.severity)
                .max()
                .unwrap_or(argus_common::events::Severity::Medium);
            trigger_reason = Some(TriggerReason::SecurityAnomaly {
                alert_count,
                max_severity: format!("{:?}", max_sev),
            });
        } else if let Some(ref end) = session_end_event {
            // Trigger A: Session Ended / SSH Client Detached
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
            // Trigger B: Dynamic Idle Timeout (e.g. 60m Shell vs 60m AI)
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
            } else if config.periodic_rollup_secs > 0
                && !unnotified_session.activities.is_empty()
                && idle_secs < 900
            {
                // Trigger C: Periodic Rollup for continuous active work (e.g. 60m of continuous session)
                let gap_threshold = chrono::Duration::seconds(threshold_secs as i64);
                let mut streak_start = unnotified_events
                    .first()
                    .map(|e| e.timestamp())
                    .unwrap_or(session_created_at);
                let mut prev_ts = streak_start;

                for ev in &unnotified_events {
                    let ts = ev.timestamp();
                    if ts.signed_duration_since(prev_ts) > gap_threshold {
                        streak_start = ts;
                    }
                    prev_ts = ts;
                }

                let continuous_work_secs = last_activity
                    .signed_duration_since(streak_start)
                    .num_seconds()
                    .max(0) as u64;

                if continuous_work_secs >= config.periodic_rollup_secs {
                    let elapsed_mins = (continuous_work_secs + 59) / 60;
                    trigger_reason = Some(TriggerReason::PeriodicRollup { elapsed_mins });
                }
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

        // Security bypass: Any security anomalies detected by RuleEngine must NEVER be suppressed as noise
        let has_security_alerts = events
            .iter()
            .any(|e| !RuleEngine::inspect_event(e).is_empty());
        if has_security_alerts {
            return (false, None);
        }

        // Filter 1: Zero reconstructed commands or empty activities (e.g. bare connection, ANSI focus in/out, terminal query pings)
        if session.total_commands == 0 || session.activities.is_empty() {
            return (
                true,
                Some(format!(
                    "Trivial empty session ({} bytes, 0 commands)",
                    session.total_input_bytes
                )),
            );
        }

        // Filter 2: All reconstructed commands are trivial commands (e.g. `exit`, `logout`, `clear`, `w`, `uptime`, `pwd`)
        let all_trivial = session.activities.iter().all(|act| {
            let cmd = act.content.trim().to_lowercase();
            let first_token = cmd.split_whitespace().next().unwrap_or("");
            config.trivial_commands.iter().any(|t| t == first_token)
        });

        if all_trivial {
            return (
                true,
                Some("Suppressed trivial maintenance/navigation commands".to_string()),
            );
        }

        // Filter 3: Pure environment sourcing / wrapper commands (e.g. `set -a && source ...`, `export ...`)
        let all_env_wrappers = session.activities.iter().all(|act| {
            let cmd = act.content.trim().to_lowercase();
            cmd.starts_with("set -a && source")
                || cmd.starts_with("set -a ; source")
                || cmd.starts_with("source ")
                || (cmd.starts_with(". ") && !cmd.starts_with("./"))
                || cmd.starts_with("export ")
        });

        if all_env_wrappers && session.activities.len() <= 2 {
            return (
                true,
                Some("Suppressed environment wrapper session".to_string()),
            );
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

    #[test]
    fn test_noise_filter_suppresses_focus_and_zero_commands() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default();
        let start = Utc::now() - Duration::minutes(10);

        // Terminal focus-in sequence (\x1b[I = 3 bytes) without any command
        let focus_event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"\x1b[I".to_vec(), false).with_timestamp(start),
        );

        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[focus_event],
            0,
            start + Duration::minutes(5),
            &config,
        );

        assert!(!eval.should_notify);
        assert!(eval.is_noise);
    }

    #[test]
    fn test_security_alert_not_suppressed_even_without_command() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default();
        let start = Utc::now() - Duration::minutes(10);

        // Raw paste containing AWS Secret Key without executing newline
        let secret_paste = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid,
                1,
                100,
                b"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_vec(),
                true,
            )
            .with_timestamp(start),
        );

        // Check IMMEDIATELY (2 seconds after event, well before 15m idle)
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[secret_paste],
            0,
            start + Duration::seconds(2),
            &config,
        );

        assert!(eval.should_notify);
        assert!(!eval.is_noise);
        match eval.trigger_reason {
            Some(TriggerReason::SecurityAnomaly { alert_count, .. }) => {
                assert_eq!(alert_count, 1);
            }
            other => panic!("Expected immediate SecurityAnomaly trigger, got {:?}", other),
        }
    }

    #[test]
    fn test_env_wrapper_noise_filter() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default();
        let start = Utc::now() - Duration::minutes(20);

        // Subshell that only sources an environment file
        let env_event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(
                sid,
                1,
                100,
                b"set -a && source /path/to/.env\n".to_vec(),
                true,
            )
            .with_timestamp(start),
        );

        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[env_event],
            0,
            start + Duration::minutes(20),
            &config,
        );

        assert!(!eval.should_notify);
        assert!(eval.is_noise);
        assert_eq!(
            eval.noise_reason,
            Some("Suppressed environment wrapper session".to_string())
        );
    }

    #[test]
    fn test_periodic_rollup_triggers_after_1hr_continuous_work() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default(); // 60m idle, 60m rollup
        let start = Utc::now() - Duration::minutes(70);

        // Continuous typing every 5 minutes from T=0 to T=65m
        let mut events = Vec::new();
        for m in (0..=65).step_by(5) {
            let cmd = format!("cargo build --step {}\n", m);
            events.push(AuditEvent::KeystrokeInput(
                KeystrokeInput::new(sid, events.len() as u64 + 1, 100, cmd.into_bytes(), true)
                    .with_timestamp(start + Duration::minutes(m)),
            ));
        }

        // Evaluate at T=66m (idle is 1 minute, work duration is 65 minutes >= 60m rollup)
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &events,
            0,
            start + Duration::minutes(66),
            &config,
        );

        assert!(eval.should_notify);
        assert!(!eval.is_noise);
        match eval.trigger_reason {
            Some(TriggerReason::PeriodicRollup { elapsed_mins }) => {
                assert_eq!(elapsed_mins, 65);
            }
            other => panic!("Expected PeriodicRollup, got {:?}", other),
        }
    }

    #[test]
    fn test_periodic_rollup_does_not_trigger_when_user_is_idle() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default(); // 60m idle, 60m rollup
        let start = Utc::now() - Duration::minutes(65);

        // User typed for 10 minutes, then was AFK for 50 minutes
        let mut events = Vec::new();
        for m in [0, 5, 10] {
            let cmd = format!("git status -s {}\n", m);
            events.push(AuditEvent::KeystrokeInput(
                KeystrokeInput::new(sid, events.len() as u64 + 1, 100, cmd.into_bytes(), true)
                    .with_timestamp(start + Duration::minutes(m)),
            ));
        }

        // Evaluate at T=60m: idle is 50 minutes (< 60m threshold), total span is 60m.
        // Should NOT fire PeriodicRollup because user is currently idle/abandoned (idle >= 15m),
        // and should NOT fire IdleTimeout because idle < 60m.
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &events,
            0,
            start + Duration::minutes(60),
            &config,
        );

        assert!(!eval.should_notify);
        assert_eq!(eval.trigger_reason, None);
    }

    #[test]
    fn test_idle_timeout_triggers_at_1hr_idle() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default(); // 60m idle
        let start = Utc::now() - Duration::minutes(75);

        let event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"npm run build\n".to_vec(), true)
                .with_timestamp(start),
        );

        // Evaluate at T=61m after event (idle is 61 minutes >= 60m threshold)
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[event],
            0,
            start + Duration::minutes(61),
            &config,
        );

        assert!(eval.should_notify);
        match eval.trigger_reason {
            Some(TriggerReason::IdleTimeout { idle_secs, threshold_secs }) => {
                assert!(idle_secs >= 3600);
                assert_eq!(threshold_secs, 3600);
            }
            other => panic!("Expected IdleTimeout, got {:?}", other),
        }
    }

    #[test]
    fn test_immediate_security_alert_bypasses_1hr_periodic_and_idle() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default(); // 60m thresholds
        let start = Utc::now() - Duration::minutes(1);

        let sudo_event = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"sudo -i\n".to_vec(), true)
                .with_timestamp(start),
        );

        // Check after just 2 seconds
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            start,
            &[sudo_event],
            0,
            start + Duration::seconds(2),
            &config,
        );

        assert!(eval.should_notify);
        match eval.trigger_reason {
            Some(TriggerReason::SecurityAnomaly { alert_count, max_severity }) => {
                assert_eq!(alert_count, 1);
                assert_eq!(max_severity, "Medium");
            }
            other => panic!("Expected immediate SecurityAnomaly, got {:?}", other),
        }
    }

    #[test]
    fn test_periodic_rollup_ignores_ancient_noise_gap() {
        let sid = Uuid::new_v4();
        let config = TriggerConfig::default(); // 60m thresholds
        let yesterday = Utc::now() - Duration::hours(24);
        let today = Utc::now() - Duration::minutes(10);

        // Event from yesterday
        let ev1 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 1, 100, b"ls -la\n".to_vec(), true)
                .with_timestamp(yesterday),
        );

        // Events today (10 minutes ago, 5 minutes ago)
        let ev2 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 2, 100, b"cargo check\n".to_vec(), true)
                .with_timestamp(today),
        );
        let ev3 = AuditEvent::KeystrokeInput(
            KeystrokeInput::new(sid, 3, 100, b"cargo test\n".to_vec(), true)
                .with_timestamp(today + Duration::minutes(5)),
        );

        // Evaluate at today + 6m: idle is 1 minute, active work today is only 5 minutes.
        let eval = AiAwareTriggerEvaluator::evaluate(
            sid,
            yesterday,
            &[ev1, ev2, ev3],
            0,
            today + Duration::minutes(6),
            &config,
        );

        // Should NOT trigger PeriodicRollup (continuous work is only 5 mins today, not 24h)
        assert!(!eval.should_notify);
        assert_eq!(eval.trigger_reason, None);
    }
}
