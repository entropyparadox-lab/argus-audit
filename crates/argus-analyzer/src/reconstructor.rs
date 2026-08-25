use argus_common::events::AuditEvent;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::sync::LazyLock;

static ANSI_ESCAPE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Matches ANSI escape sequences: CSI (\x1b[...), OSC (\x1b]...), DCS (\x1bP...), APC/PM/SOS, and single escapes
    Regex::new(
        r"(?x)
        \x1b\[[0-9:;<=>?]*[\x20-\x2F]*[@-~] |       # CSI sequences (SGR mouse, colors, cursor, focus, DA/DSR queries, bracketed paste)
        \x1b\][^\x07\x1b]*(?:\x07|\x1b\\)? |        # OSC sequences (window titles, OSC 52 clipboard, color palette)
        \x1bP[^\x1b]*(?:\x1b\\)? |                  # DCS sequences (device control / term responses)
        \x1b[_^X][^\x1b]*(?:\x1b\\)? |              # APC / PM / SOS sequences
        \x1b[\x20-\x2F]*[\x30-\x7E] |               # 2-byte escape sequences (SS2/SS3, \x1bO[A-Z], \x1bM, etc.)
        \x1b |                                      # Any dangling bare ESC
        \[<[0-9;]+[Mm] |                            # Orphaned SGR mouse events without ESC
        \[>[0-9;]+c |                               # Orphaned secondary DA without ESC
        \[\?[0-9;]+[a-zA-Z] |                       # Orphaned private mode/DA/DSR without ESC
        [\x00-\x06\x0b\x0c\x0e-\x1a\x1c-\x1f]       # Control characters except \a, \b, \t, \n, \r
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

    /// Check if an extracted line is terminal emulator noise, DA inquiry response, or editor navigation spam
    pub fn is_terminal_noise_or_navigation(trimmed: &str) -> bool {
        if trimmed.is_empty() {
            return true;
        }

        // 1. Terminal Device Attribute & Status inquiry responses: [>64;2500;0c, [?64;1;2c, >64;2500;0c, ?997;1n, 4;1008;1432t
        if (trimmed.starts_with("[>")
            || trimmed.starts_with('>')
            || trimmed.starts_with("[?")
            || trimmed.starts_with('?')
            || trimmed.starts_with("[<")
            || trimmed.starts_with('<'))
            && (trimmed.ends_with('c')
                || trimmed.ends_with('n')
                || trimmed.ends_with('t')
                || trimmed.ends_with('R')
                || trimmed.ends_with('M')
                || trimmed.ends_with('m'))
        {
            return true;
        }

        // 2. Orphaned SGR mouse tracking fragments (e.g. [<35;..., <35;...)
        if trimmed.starts_with("[<")
            || trimmed.starts_with('<')
            || (trimmed.contains("[<") && (trimmed.ends_with('M') || trimmed.ends_with('m')))
        {
            return true;
        }

        // 3. Repetitive single character navigation spam (e.g. jjjjjjjj, kkkkkk, hhhhh, llllll)
        if trimmed.len() >= 4 {
            let first_char = trimmed.chars().next().unwrap();
            if trimmed.chars().all(|c| c == first_char) {
                return true;
            }
            // Repetitive motion with trailing vim command (e.g. jjjjjjjjjjj:q)
            if (first_char == 'j' || first_char == 'k' || first_char == 'h' || first_char == 'l')
                && trimmed
                    .trim_end_matches(":q")
                    .trim_end_matches(":wq")
                    .trim_end_matches(":x")
                    .trim_end_matches(":q!")
                    .chars()
                    .all(|c| c == first_char)
            {
                return true;
            }
        }

        // 4. Isolated TUI editor internal commands/motions (:wq, :q!, ggO, ZZ)
        if matches!(
            trimmed,
            ":q" | ":wq" | ":w" | ":x" | ":q!" | ":w!" | "ZZ" | "ZQ" | "ggO" | "gg" | "G"
        ) {
            return true;
        }

        false
    }

    /// Reconstruct a stream of audit events into clean chronological activities
    pub fn reconstruct(events: &[AuditEvent]) -> ReconstructedSession {
        let mut session = ReconstructedSession::default();
        let mut line_buffer = String::new();
        let mut raw_bytes_buffer = Vec::new();
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
                        // Flush any pending raw byte buffer first
                        if !raw_bytes_buffer.is_empty() {
                            let text = String::from_utf8_lossy(&raw_bytes_buffer);
                            Self::process_typed_chars(
                                &text,
                                &mut line_buffer,
                                &mut line_start_time,
                                key.timestamp,
                                &mut session,
                                in_ai_session_mode,
                            );
                            raw_bytes_buffer.clear();
                        }

                        // Flush any pending typed buffer
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
                            if !trimmed.is_empty()
                                && !Self::is_terminal_noise_or_navigation(trimmed)
                            {
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
                        // Accumulate raw keystroke bytes to handle UTF-8 multibyte boundary across reads
                        raw_bytes_buffer.extend_from_slice(&key.data);

                        let (valid_str, remaining_bytes) = match std::str::from_utf8(&raw_bytes_buffer) {
                            Ok(s) => (s.to_string(), Vec::new()),
                            Err(e) => {
                                let valid_up_to = e.valid_up_to();
                                let valid_str = match std::str::from_utf8(&raw_bytes_buffer[..valid_up_to]) {
                                    Ok(s) => s.to_string(),
                                    Err(_) => String::new(),
                                };
                                let rem = match e.error_len() {
                                    Some(err_len) => raw_bytes_buffer[valid_up_to + err_len..].to_vec(),
                                    None => raw_bytes_buffer[valid_up_to..].to_vec(),
                                };
                                (valid_str, rem)
                            }
                        };
                        raw_bytes_buffer = remaining_bytes;

                        if !valid_str.is_empty() {
                            Self::process_typed_chars(
                                &valid_str,
                                &mut line_buffer,
                                &mut line_start_time,
                                key.timestamp,
                                &mut session,
                                in_ai_session_mode,
                            );
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
                    if !raw_bytes_buffer.is_empty() {
                        let text = String::from_utf8_lossy(&raw_bytes_buffer);
                        Self::process_typed_chars(
                            &text,
                            &mut line_buffer,
                            &mut line_start_time,
                            end.timestamp,
                            &mut session,
                            in_ai_session_mode,
                        );
                        raw_bytes_buffer.clear();
                    }
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
        if !raw_bytes_buffer.is_empty() {
            let text = String::from_utf8_lossy(&raw_bytes_buffer);
            Self::process_typed_chars(
                &text,
                &mut line_buffer,
                &mut line_start_time,
                session.last_activity.unwrap_or_else(Utc::now),
                &mut session,
                in_ai_session_mode,
            );
            raw_bytes_buffer.clear();
        }
        Self::flush_line_buffer(
            &mut line_buffer,
            &mut line_start_time,
            &mut session,
            in_ai_session_mode,
        );

        session
    }

    fn process_typed_chars(
        raw_text: &str,
        line_buffer: &mut String,
        line_start_time: &mut Option<DateTime<Utc>>,
        timestamp: DateTime<Utc>,
        session: &mut ReconstructedSession,
        in_ai_session_mode: bool,
    ) {
        let sanitized = Self::sanitize_terminal_text(raw_text);
        for ch in sanitized.chars() {
            if line_start_time.is_none() {
                *line_start_time = Some(timestamp);
            }

            if ch == '\r' || ch == '\n' {
                Self::flush_line_buffer(
                    line_buffer,
                    line_start_time,
                    session,
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

    fn flush_line_buffer(
        buf: &mut String,
        start_time: &mut Option<DateTime<Utc>>,
        session: &mut ReconstructedSession,
        in_ai_session_mode: bool,
    ) {
        let trimmed = buf.trim();
        if !trimmed.is_empty() && !Self::is_terminal_noise_or_navigation(trimmed) {
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

    #[test]
    fn test_editor_navigation_and_da_inquiry_filtering() {
        let sid = Uuid::new_v4();
        let events = vec![
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                1,
                100,
                b"vi ~/.ssh/config\r".to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                2,
                200,
                b"\x1b[>64;2500;0c\r".to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                3,
                300,
                b"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj:q\r".to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 4, 400, b"ggO\r".to_vec(), false)),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                5,
                500,
                b"Host test-server  HostName 1.2.3.4  User root\n".to_vec(),
                true,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 6, 600, b":wq\r".to_vec(), false)),
        ];

        let session = KeystrokeReconstructor::reconstruct(&events);
        assert_eq!(session.activities.len(), 2);
        assert_eq!(session.activities[0].content, "vi ~/.ssh/config");
        assert_eq!(
            session.activities[1].content,
            "Host test-server  HostName 1.2.3.4  User root"
        );
    }

    #[test]
    fn test_sgr_mouse_and_korean_typing_reconstruction() {
        let sid = Uuid::new_v4();
        let events = vec![
            // 1. Terminal status & SGR mouse movements
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                1,
                100,
                b"\x1b[?1;2c\x1b[>0;276;0c\x1b[<35;13;1M\x1b[<35;13;3M".to_vec(),
                false,
            )),
            // 2. Korean typing with backspaces and interleaved mouse movements
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                2,
                200,
                "제".as_bytes().to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                3,
                300,
                "가 ".as_bytes().to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                4,
                400,
                "QR 코드".as_bytes().to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                5,
                500,
                b"\x1b[<35;47;21M\x1b[<35;47;22M".to_vec(),
                false,
            )),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                6,
                600,
                " 확인 요청\r".as_bytes().to_vec(),
                false,
            )),
            // 3. Trailing mouse movements after enter
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                sid,
                7,
                700,
                b"\x1b[<35;131;45M\x1b[<35;129;46M".to_vec(),
                false,
            )),
        ];

        let session = KeystrokeReconstructor::reconstruct(&events);
        assert_eq!(session.activities.len(), 1);
        assert_eq!(session.activities[0].content, "제가 QR 코드 확인 요청");
    }

    #[test]
    fn test_split_multibyte_korean_utf8_chunks() {
        let sid = Uuid::new_v4();
        let korean_str = "한글입력";
        let bytes = korean_str.as_bytes(); // 12 bytes (4 chars * 3 bytes)

        // Split across boundary (e.g. 2 bytes in chunk 1, 1 byte in chunk 2)
        let chunk1 = bytes[..2].to_vec();
        let chunk2 = bytes[2..7].to_vec();
        let mut chunk3 = bytes[7..].to_vec();
        chunk3.push(b'\n');

        let events = vec![
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 1, 100, chunk1, false)),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 2, 200, chunk2, false)),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(sid, 3, 300, chunk3, false)),
        ];

        let session = KeystrokeReconstructor::reconstruct(&events);
        assert_eq!(session.activities.len(), 1);
        assert_eq!(session.activities[0].content, "한글입력");
    }
}
