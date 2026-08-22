use anyhow::{Context, Result};
use argus_analyzer::{ClaudePromptParser, SemanticSummarizer, SessionCorrelator};
use argus_collector::{AuditStore, SessionSummary};
use argus_common::events::AuditEvent;
use clap::{Parser, Subcommand};
use reqwest::Client;
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "argus", author, version, about = "Argus Audit CLI Tool")]
struct Cli {
    /// Remote collector URL (if querying over HTTP instead of direct SQLite)
    #[arg(short, long, env = "ARGUS_COLLECTOR_URL")]
    collector: Option<String>,

    /// Local SQLite database path (default: audit.db)
    #[arg(long, default_value = "audit.db", env = "ARGUS_DB_PATH")]
    db: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List recorded developer sessions
    Sessions {
        /// Number of sessions to display
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Replay keystrokes and inputs of a specific session
    Replay {
        /// Session UUID
        session_id: String,

        /// Replay speed multiplier (e.g. 1.0 = real-time, 2.0 = 2x speed, 0 = instant)
        #[arg(short, long, default_value = "1.0")]
        speed: f64,
    },

    /// Dump all raw events of a session in JSONL
    Dump {
        /// Session UUID
        session_id: String,
    },

    /// Correlate session activity and build LLM semantic analysis report
    Analyze {
        /// Session UUID
        session_id: String,

        /// Optional path to Claude CLI history.jsonl
        #[arg(long)]
        claude_history: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sessions { limit } => {
            let sessions = fetch_sessions(&cli.collector, &cli.db, limit).await?;
            print_sessions_table(&sessions);
        }
        Commands::Replay { session_id, speed } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let events = fetch_events(&cli.collector, &cli.db, uid).await?;
            replay_session(events, speed)?;
        }
        Commands::Dump { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let events = fetch_events(&cli.collector, &cli.db, uid).await?;
            for ev in events {
                println!("{}", serde_json::to_string(&ev)?);
            }
        }
        Commands::Analyze {
            session_id,
            claude_history,
        } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let events = fetch_events(&cli.collector, &cli.db, uid).await?;

            let prompts = if let Some(path) = claude_history {
                ClaudePromptParser::parse_history_file(path).unwrap_or_default()
            } else {
                Vec::new()
            };

            let report = SessionCorrelator::correlate_session(uid, &events, &prompts);
            let prompt = SemanticSummarizer::build_llm_prompt(&report);

            println!("{prompt}");
        }
    }

    Ok(())
}

async fn fetch_sessions(
    collector: &Option<String>,
    db_path: &PathBuf,
    limit: usize,
) -> Result<Vec<SessionSummary>> {
    if let Some(url) = collector {
        let client = Client::new();
        let resp = client
            .get(format!("{url}/api/v1/sessions?limit={limit}"))
            .send()
            .await?
            .json::<Vec<SessionSummary>>()
            .await?;
        Ok(resp)
    } else {
        let store = AuditStore::new(db_path)?;
        store.list_sessions(limit)
    }
}

async fn fetch_events(
    collector: &Option<String>,
    db_path: &PathBuf,
    session_id: Uuid,
) -> Result<Vec<AuditEvent>> {
    if let Some(url) = collector {
        let client = Client::new();
        let resp = client
            .get(format!("{url}/api/v1/sessions/{session_id}/events"))
            .send()
            .await?
            .json::<Vec<AuditEvent>>()
            .await?;
        Ok(resp)
    } else {
        let store = AuditStore::new(db_path)?;
        store.get_session_events(session_id)
    }
}

fn print_sessions_table(sessions: &[SessionSummary]) {
    if sessions.is_empty() {
        println!("No recorded sessions found.");
        return;
    }

    println!(
        "{:<36}  {:<20}  {:<12}  {:<16}  {:<24}  {:<10}",
        "SESSION ID", "TIMESTAMP (UTC)", "USER", "CLIENT IP", "SSH KEY / COMMENT", "DURATION"
    );
    println!("{:-<125}", "");

    for s in sessions {
        let ip_display = s.client_ip.clone().unwrap_or_else(|| "local".into());
        let comment_display = s.ssh_key_comment.clone().unwrap_or_else(|| "-".into());
        let dur_display = s
            .duration_ms
            .map(|d| format!("{:.1}s", d as f64 / 1000.0))
            .unwrap_or_else(|| "in-progress".into());

        println!(
            "{:<36}  {:<20}  {:<12}  {:<16}  {:<24}  {:<10}",
            s.session_id,
            s.created_at.format("%Y-%m-%d %H:%M:%S"),
            s.username,
            ip_display,
            comment_display,
            dur_display
        );
    }
}

fn replay_session(events: Vec<AuditEvent>, speed: f64) -> Result<()> {
    println!("\n=== Starting Replay for Session (Speed: {}x) ===", speed);
    let mut last_ms = 0u64;

    for event in events {
        match event {
            AuditEvent::SessionInit(init) => {
                println!(
                    "\n[Session Started: {} on {}@{} ({}:{})]",
                    init.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    init.username,
                    init.hostname,
                    init.client_ip.as_deref().unwrap_or("local"),
                    init.client_port.unwrap_or(0)
                );
                println!("--------------------------------------------------");
            }
            AuditEvent::KeystrokeInput(key) => {
                if speed > 0.0 && key.elapsed_ms > last_ms {
                    let delay_ms = ((key.elapsed_ms - last_ms) as f64 / speed) as u64;
                    // Cap delay to 2 seconds to avoid waiting through long pauses
                    thread::sleep(Duration::from_millis(delay_ms.min(2000)));
                }
                last_ms = key.elapsed_ms;

                let text = key.as_str_lossy();
                print!("{text}");
                let _ = stdout().flush();
            }
            AuditEvent::SessionEnd(end) => {
                println!("\n--------------------------------------------------");
                println!(
                    "[Session Ended: Duration {:.1}s, Input Bytes: {}, Exit Status: {:?}]\n",
                    end.duration_ms as f64 / 1000.0,
                    end.total_input_bytes,
                    end.exit_status
                );
            }
            _ => {}
        }
    }

    Ok(())
}
