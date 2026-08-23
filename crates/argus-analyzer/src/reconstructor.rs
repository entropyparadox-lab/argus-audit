use argus_common::events::AuditEvent;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::sync::LazyLock;

static ANSI_ESCAPE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches ANSI escape sequences: CSI (\x1b[...), OSC (\x1b]...), DCS (\x1bP...), and single escapes
    Regex::new(
        r"(?x)
        \x1b\[[0-9;?*!$]*[a-zA-Z~] |  # CSI sequences (colors, cursor, focus, DA queries)
        \x1b\][^\x07\x1b]*(\x07|\x1b\\) | # OSC sequences (window titles, OSC 52 clipboard)
        \x1bP[^\x1b]*\x1b\\ |             # DCS sequences (device control / term responses)
        \x1b[_^][^\x1b]*\x1b\\ |          # APC / PM sequences
        \x1b[NnOo] |                      # Single escapes (SS2, SS3)
        [\x00-\x06\x0b\x0c\x0e-\x1a\x1c-\x1f] # Control characters except \a, \b, \t, \n, \r
    ",
    )
    .unwrap()
});

static AI_CLI_KEYWORDS: &[&str] = &[
    "claude",
    "claude-code",
    "hermes",
    "hermes-agent",
    "aider",
    "codex",
    "cursor",
    "opencode",
    "ollama",
    "serena",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityKind {
    Command,
    Paste,
    AiPrompt,
    InteractiveInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconstructedActivity {
    pub timestamp: DateTime<Utc>,
    pub content: String,
    pub kind: ActivityKind,
    pub is_ai: bool,
}

#[derive(Debug, Default, Clone)]
pub struct ReconstructedSession {
    pub activities: Vec<ReconstructedActivity>,
    pub has_ai_activity: bool,
    pub total_commands: usize,
    pub total_input_bytes: usize,
    pub first_activity: Option<DateTime<Utc>>,
    pub last_activity: Option<DateTime<Utc>>,
}

pub struct KeystrokeReconstructor;

impl KeystrokeReconstructor {
    /// Strip raw ANSI escape sequences and non-printable terminal control artifacts
    pub fn sanitize_terminal_text(input: &str) -> String {
        let cleaned = ANSI_ESCAPE_REGEX.replace_all(input, "");
        cleaned.to_string()
    }

    /// Check if a command or line represents an AI CLI tool invocation or AI interaction
    pub fn is_ai_tool_invocation(cmd: &str) -> bool {
        let trimmed = cmd.trim().to_lowercase();
        if trimmed.is_empty() {
            return false;
        }

        // Check if command starts with an AI keyword or contains AI binary invocation
        let first_word = trimmed.split_whitespace().next().unwrap_or("");
        let first_word_base = first_word.rsplit('/').next().unwrap_or(first_word);

        for &kw in AI_CLI_KEYWORDS {
            if first_word_base == kw
                || first_word_base.starts_with(&format!("{kw}-"))
                || first_word_base.starts_with(&format!("{kw}_"))
                || trimmed.starts_with(&format!("{kw} "))
                || trimmed.contains(&format!(" {kw} "))
            {
                return true;
            }
        }

        false
    }

    /// Reconstruct a stream of audit events into clean chronological activities
    pub fn reconstruct(events: &[AuditEvent]) -> ReconstructedSession {
        let mut session = ReconstructedSession::default();
        let mut line_buffer = String::new();
        let mut line_start_time = None;
        let mut in_ai_session_mode = false;

        for event in events {
            match event {
                AuditEvent::KeystrokeInput(key) => {
                    session.total_input_bytes += key.byte_len;
                    if session.first_activity.is_none() {
                        session.first_activity = Some(key.timestamp);
                    }
                    session.last_activity = Some(key.timestamp);

                    if key.is_paste {
                        // Flush any pending typed buffer first
                        Self::flush_line_buffer(
                            &mut line_buffer,
                            &mut line_start_time,
                            &mut session,
                            in_ai_session_mode,
                        );

                        // Process pasted block
                        let text = key.as_str_lossy();
                        let sanitized = Self::sanitize_terminal_text(&text);
                        for line in sanitized.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                let is_ai =
                                    in_ai_session_mode || Self::is_ai_tool_invocation(trimmed);
                                if is_ai {
                                    session.has_ai_activity = true;
                                    in_ai_session_mode = true;
                                }
                                session.total_commands += 1;
                                session.activities.push(ReconstructedActivity {
                                    timestamp: key.timestamp,
                                    content: trimmed.to_string(),
                                    kind: ActivityKind::Paste,
                                    is_ai,
                                });
                            }
                        }
                    } else {
                        // Interactive typing char by char
                        let raw_chunk = key.as_str_lossy();
                        let sanitized = Self::sanitize_terminal_text(&raw_chunk);

                        for ch in sanitized.chars() {
                            if line_start_time.is_none() {
                                line_start_time = Some(key.timestamp);
                            }

                            if ch == '\r' || ch == '\n' {
                                Self::flush_line_buffer(
                                    &mut line_buffer,
                                    &mut line_start_time,
                                    &mut session,
                                    in_ai_session_mode,
                                );
                            } else if ch == '\x7f' || ch == '\x08' {
                                // Backspace
                                line_buffer.pop();
                            } else if !ch.is_control() {
                                line_buffer.push(ch);
                            }
                        }
                    }
                }
                AuditEvent::ProcessExec(p) => {
                    if session.first_activity.is_none() {
                        session.first_activity = Some(p.timestamp);
                    }
                    session.last_activity = Some(p.timestamp);

                    let cmdline = p.argv.join(" ");
                    let is_ai = Self::is_ai_tool_invocation(&cmdline)
                        || Self::is_ai_tool_invocation(&p.comm);
                    if is_ai {
                        session.has_ai_activity = true;
                        in_ai_session_mode = true;
                    }
                }
                AuditEvent::PromptTrace(p) => {
                    if session.first_activity.is_none() {
                        session.first_activity = Some(p.timestamp);
                    }
                    session.last_activity = Some(p.timestamp);
                    session.has_ai_activity = true;
                    in_ai_session_mode = true;

                    session.activities.push(ReconstructedActivity {
                        timestamp: p.timestamp,
                        content: p.prompt.clone(),
                        kind: ActivityKind::AiPrompt,
                        is_ai: true,
                    });
                }
                AuditEvent::SessionEnd(end) => {
                    session.last_activity = Some(end.timestamp);
                    Self::flush_line_buffer(
                        &mut line_buffer,
                        &mut line_start_time,
                        &mut session,
                        in_ai_session_mode,
                    );
                }
                _ => {}
            }
        }

        // Final flush if any uncommitted typed buffer remains
        Self::flush_line_buffer(
            &mut line_buffer,
            &mut line_start_time,
            &mut session,
            in_ai_session_mode,
        );

        session
    }

    fn flush_line_buffer(
        buf: &mut String,
        start_time: &mut Option<DateTime<Utc>>,
        session: &mut ReconstructedSession,
        in_ai_session_mode: bool,
    ) {
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            let ts = start_time.unwrap_or_else(Utc::now);
            let is_ai = in_ai_session_mode || Self::is_ai_tool_invocation(trimmed);
            if is_ai {
                session.has_ai_activity = true;
            }
            session.total_commands += 1;
            session.activities.push(ReconstructedActivity {
                timestamp: ts,
                content: trimmed.to_string(),
                kind: if is_ai {
                    ActivityKind::AiPrompt
                } else {
                    ActivityKind::Command
                },
                is_ai,
            });
        }
        buf.clear();
        *start_time = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argus_common::events::KeystrokeInput;
    use uuid::Uuid;

    #[test]
    fn test_sanitize_ansi_escapes() {
        let raw = "\x1b[?64;1;2c\x1b[Igit status\x1b[O\r\n";
        let clean = KeystrokeReconstructor::sanitize_terminal_text(raw);
        assert_eq!(clean, "git status\r\n");
    }

    #[test]
    fn test_backspace_and_line_reconstruction() {
        let sid = Uuid::new_v4();
        let events = vec![
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                1,
                100,
                b"gitt\x7f status\r".to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                2,
                200,
                b"cargo test --package ep-audit\n".to_vec(),
                false,
            )),
        ];

        let session = KeystrokeReconstructor::reconstruct(&events);
        assert_eq!(session.activities.len(), 2);
        assert_eq!(session.activities[0].content, "git status");
        assert_eq!(
            session.activities[1].content,
            "cargo test --package ep-audit"
        );
        assert!(!session.has_ai_activity);
    }

    #[test]
    fn test_ai_tool_detection() {
        let sid = Uuid::new_v4();
        let events = vec![AuditEvent::KeystrokeInput(KeystrokeInput::new(
            sid,
            1,
            100,
            b"claude 'Refactor billing logic'\n".to_vec(),
            false,
        ))];

        let session = KeystrokeReconstructor::reconstruct(&events);
        assert_eq!(session.activities.len(), 1);
        assert!(session.has_ai_activity);
        assert!(session.activities[0].is_ai);
    }
}
