use anyhow::Result;
use argus_common::events::PromptTrace;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ClaudeHistoryEntry {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

pub struct ClaudePromptParser;

impl ClaudePromptParser {
    /// Parse Claude CLI history.jsonl into structured PromptTrace events
    pub fn parse_history_file<P: AsRef<Path>>(path: P) -> Result<Vec<PromptTrace>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut traces = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<ClaudeHistoryEntry>(&line) {
                if let Some(prompt_text) = entry.prompt {
                    let ts = entry
                        .timestamp
                        .and_then(|t| DateTime::parse_from_rfc3339(&t).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);

                    traces.push(PromptTrace {
                        session_id: None,
                        timestamp: ts,
                        tool: "claude-code".to_string(),
                        prompt: prompt_text,
                        project_path: entry.project,
                        model: entry.model,
                        assistant_response_summary: None,
                    });
                }
            }
        }

        Ok(traces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_claude_history() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"{{"timestamp": "2026-08-22T14:12:00Z", "prompt": "Fix database migration bug", "project": "/home/user/project", "model": "claude-3-7-sonnet"}}"#
        )
        .unwrap();
        writeln!(
            tmp,
            r#"{{"timestamp": "2026-08-22T14:15:00Z", "prompt": "Run cargo test and build binary"}}"#
        )
        .unwrap();

        let traces = ClaudePromptParser::parse_history_file(tmp.path()).unwrap();
        assert_eq!(traces.len(), 2);
        assert_eq!(traces[0].prompt, "Fix database migration bug");
        assert_eq!(traces[0].project_path, Some("/home/user/project".into()));
        assert_eq!(traces[1].prompt, "Run cargo test and build binary");
    }
}
