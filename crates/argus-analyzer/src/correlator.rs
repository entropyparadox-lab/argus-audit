use crate::reconstructor::{ActivityKind, KeystrokeReconstructor};
use crate::rules::{AnomalyAlert, RuleEngine};
use argus_common::events::{AuditEvent, PromptTrace, SessionInit};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub content: String,
    pub alerts: Vec<AnomalyAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedSessionReport {
    pub session_id: Uuid,
    pub identity: Option<SessionInit>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub total_input_bytes: u64,
    pub ai_prompts: Vec<PromptTrace>,
    pub timeline: Vec<TimelineEntry>,
    pub alerts: Vec<AnomalyAlert>,
}

pub struct SessionCorrelator;

impl SessionCorrelator {
    /// Correlate a stream of raw audit events and Claude prompts into a coherent session report
    pub fn correlate_session(
        session_id: Uuid,
        events: &[AuditEvent],
        prompts: &[PromptTrace],
    ) -> CorrelatedSessionReport {
        let mut identity = None;
        let mut start_time = Utc::now();
        let mut end_time = None;
        let mut total_input_bytes = 0u64;
        let mut timeline = Vec::new();
        let mut all_alerts = Vec::new();

        // 1. Process raw audit events
        for event in events {
            let event_alerts = RuleEngine::inspect_event(event);
            all_alerts.extend(event_alerts.clone());

            match event {
                AuditEvent::SessionInit(init) => {
                    start_time = init.timestamp;
                    identity = Some(init.clone());
                    timeline.push(TimelineEntry {
                        timestamp: init.timestamp,
                        category: "login".to_string(),
                        content: format!(
                            "User {} logged in from {} via {}",
                            init.username,
                            init.client_ip.as_deref().unwrap_or("local"),
                            init.tty
                        ),
                        alerts: event_alerts,
                    });
                }
                AuditEvent::KeystrokeInput(key) => {
                    total_input_bytes += key.byte_len as u64;
                }
                AuditEvent::ProcessExec(proc) => {
                    timeline.push(TimelineEntry {
                        timestamp: proc.timestamp,
                        category: "process_exec".to_string(),
                        content: proc.argv.join(" "),
                        alerts: event_alerts,
                    });
                }
                AuditEvent::SessionEnd(end) => {
                    end_time = Some(end.timestamp);
                    timeline.push(TimelineEntry {
                        timestamp: end.timestamp,
                        category: "logout".to_string(),
                        content: format!(
                            "Session ended (Duration: {:.1}s, Status: {:?})",
                            end.duration_ms as f64 / 1000.0,
                            end.exit_status
                        ),
                        alerts: event_alerts,
                    });
                }
                _ => {}
            }
        }

        // 2. Add cleanly reconstructed activities into timeline
        let reconstructed = KeystrokeReconstructor::reconstruct(events);
        for act in reconstructed.activities {
            let category = match act.kind {
                ActivityKind::Command => "command",
                ActivityKind::Paste => "clipboard_paste",
                ActivityKind::AiPrompt => "ai_prompt",
                ActivityKind::InteractiveInput => "user_input",
            };
            timeline.push(TimelineEntry {
                timestamp: act.timestamp,
                category: category.to_string(),
                content: act.content,
                alerts: Vec::new(),
            });
        }

        // 3. Correlate AI Prompts that occurred within the session timeframe
        let mut session_prompts = Vec::new();
        for prompt in prompts {
            session_prompts.push(prompt.clone());
            timeline.push(TimelineEntry {
                timestamp: prompt.timestamp,
                category: "ai_prompt".to_string(),
                content: format!("[{}] {}", prompt.tool, prompt.prompt),
                alerts: Vec::new(),
            });
        }

        // Sort timeline chronologically
        timeline.sort_by_key(|entry| entry.timestamp);

        CorrelatedSessionReport {
            session_id,
            identity,
            start_time,
            end_time,
            total_input_bytes,
            ai_prompts: session_prompts,
            timeline,
            alerts: all_alerts,
        }
    }
}
