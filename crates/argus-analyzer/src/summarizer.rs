use crate::correlator::CorrelatedSessionReport;

pub struct SemanticSummarizer;

impl SemanticSummarizer {
    /// Build an LLM analysis prompt from the correlated session report
    pub fn build_llm_prompt(report: &CorrelatedSessionReport) -> String {
        let username = report
            .identity
            .as_ref()
            .map(|i| i.username.as_str())
            .unwrap_or("unknown");
        let client_ip = report
            .identity
            .as_ref()
            .and_then(|i| i.client_ip.as_deref())
            .unwrap_or("local");
        let ssh_comment = report
            .identity
            .as_ref()
            .and_then(|i| i.ssh_key_comment.as_deref())
            .unwrap_or("none");

        let mut prompt = String::new();
        prompt.push_str("You are an expert security auditor and engineering analyst.\n");
        prompt.push_str("Analyze the following developer/AI terminal session and generate a concise executive summary:\n\n");
        prompt.push_str(&format!("- Session ID: {}\n", report.session_id));
        prompt.push_str(&format!(
            "- User: {} (SSH Key: {}, IP: {})\n",
            username, ssh_comment, client_ip
        ));
        prompt.push_str(&format!(
            "- Start Time: {}\n",
            report.start_time.to_rfc3339()
        ));
        if let Some(end) = report.end_time {
            prompt.push_str(&format!("- End Time: {}\n", end.to_rfc3339()));
        }
        prompt.push_str(&format!(
            "- Total Input Bytes: {}\n",
            report.total_input_bytes
        ));
        prompt.push_str(&format!("- Anomaly Alerts: {}\n\n", report.alerts.len()));

        if !report.alerts.is_empty() {
            prompt.push_str("### ⚠️ Security Alerts Detected:\n");
            for a in &report.alerts {
                prompt.push_str(&format!(
                    "  * [{:?}] {}: {}\n",
                    a.severity, a.description, a.evidence
                ));
            }
            prompt.push('\n');
        }

        prompt.push_str("### 📜 Session Activity Timeline:\n");
        for t in &report.timeline {
            prompt.push_str(&format!(
                "[{}] [{}] {}\n",
                t.timestamp.format("%H:%M:%S"),
                t.category,
                t.content
            ));
        }

        prompt.push_str("\n### Required Analysis Output:\n");
        prompt.push_str("1. **Executive Summary**: 2-3 sentences explaining what tasks the developer performed.\n");
        prompt.push_str("2. **AI Assistance vs Human Direct Actions**: Which commands were driven by AI prompts versus manual developer typing.\n");
        prompt.push_str("3. **Security Assessment**: Verification of any secret leaks, anomalous commands, or privilege risks.\n");

        prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlator::SessionCorrelator;
    use argus_common::events::{AuditEvent, KeystrokeInput, PromptTrace, SessionInit};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_summarizer_prompt_generation() {
        let session_id = Uuid::new_v4();
        let init = AuditEvent::SessionInit(SessionInit {
            session_id,
            timestamp: Utc::now(),
            hostname: "dev-01".into(),
            username: "ubuntu".into(),
            tty: "pts/1".into(),
            client_ip: Some("10.0.0.5".into()),
            client_port: Some(22),
            ssh_key_fingerprint: Some("SHA256:xyz".into()),
            ssh_key_comment: Some("dev_lee@company.com".into()),
            env_context: None,
        });

        let key = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            100,
            b"claude 'Refactor login auth handler'\n".to_vec(),
            false,
        ));

        let prompt = PromptTrace {
            session_id: Some(session_id),
            timestamp: Utc::now(),
            tool: "claude-code".into(),
            prompt: "Refactor login auth handler".into(),
            project_path: Some("/home/ubuntu/app".into()),
            model: Some("claude-3-7-sonnet".into()),
            assistant_response_summary: None,
        };

        let report = SessionCorrelator::correlate_session(session_id, &[init, key], &[prompt]);
        let prompt_text = SemanticSummarizer::build_llm_prompt(&report);

        assert!(prompt_text.contains("Session ID:"));
        assert!(prompt_text.contains("dev_lee@company.com"));
        assert!(prompt_text.contains("Refactor login auth handler"));
    }
}
