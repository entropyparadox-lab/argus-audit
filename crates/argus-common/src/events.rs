use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity level for security alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Categories of kernel and system security events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    SensitiveFileWrite,
    SensitiveFileRead,
    KernelModuleLoad,
    KernelModuleUnload,
    OutboundC2Attempt,
    PrivilegeEscalationAttempt,
    TimeModification,
    AuditRuleTamperAttempt,
    Unknown(String),
}

/// 1. Session Initialization (Identity mapping upon SSH/Local login)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInit {
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub username: String,
    pub tty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_context: Option<std::collections::HashMap<String, String>>,
}

/// 2. Keystroke and Stdin Input (Human / AI input, Paste capturing)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystrokeInput {
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub seq: u64,
    pub elapsed_ms: u64,
    /// Raw input data (UTF-8 or binary bytes)
    pub data: Vec<u8>,
    /// True if heuristic or bracketed paste mode detected a bulk paste
    pub is_paste: bool,
    /// Length of the captured slice
    pub byte_len: usize,
}

impl KeystrokeInput {
    pub fn new(session_id: Uuid, seq: u64, elapsed_ms: u64, data: Vec<u8>, is_paste: bool) -> Self {
        let byte_len = data.len();
        Self {
            session_id,
            timestamp: Utc::now(),
            seq,
            elapsed_ms,
            data,
            is_paste,
            byte_len,
        }
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }

    /// Helper to get input as UTF-8 lossy string
    pub fn as_str_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.data)
    }
}

/// 3. Process Execution Event (execve syscall audit)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessExec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// 4. AI Agent Prompt Trace (Claude Code, AI CLI sessions)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptTrace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub tool: String,
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assistant_response_summary: Option<String>,
}

/// 5. Kernel Security Alert (Rootkit, tamper, C2 network connections)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSecurityEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub event_kind: SecurityEventKind,
    pub severity: Severity,
    pub source: String,
    pub target: String,
    pub details: serde_json::Value,
}

/// 6. Session Termination
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    pub session_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub total_input_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
}

/// Root Audit Event Enum encapsulating all event types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum AuditEvent {
    SessionInit(SessionInit),
    KeystrokeInput(KeystrokeInput),
    ProcessExec(ProcessExec),
    PromptTrace(PromptTrace),
    KernelSecurity(KernelSecurityEvent),
    SessionEnd(SessionEnd),
}

impl AuditEvent {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            AuditEvent::SessionInit(e) => e.timestamp,
            AuditEvent::KeystrokeInput(e) => e.timestamp,
            AuditEvent::ProcessExec(e) => e.timestamp,
            AuditEvent::PromptTrace(e) => e.timestamp,
            AuditEvent::KernelSecurity(e) => e.timestamp,
            AuditEvent::SessionEnd(e) => e.timestamp,
        }
    }

    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            AuditEvent::SessionInit(e) => Some(e.session_id),
            AuditEvent::KeystrokeInput(e) => Some(e.session_id),
            AuditEvent::ProcessExec(e) => e.session_id,
            AuditEvent::PromptTrace(e) => e.session_id,
            AuditEvent::KernelSecurity(e) => e.session_id,
            AuditEvent::SessionEnd(e) => Some(e.session_id),
        }
    }

    pub fn event_type_name(&self) -> &'static str {
        match self {
            AuditEvent::SessionInit(_) => "session_init",
            AuditEvent::KeystrokeInput(_) => "keystroke_input",
            AuditEvent::ProcessExec(_) => "process_exec",
            AuditEvent::PromptTrace(_) => "prompt_trace",
            AuditEvent::KernelSecurity(_) => "kernel_security",
            AuditEvent::SessionEnd(_) => "session_end",
        }
    }
}
