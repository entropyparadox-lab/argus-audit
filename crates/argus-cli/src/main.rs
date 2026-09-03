use anyhow::{Context, Result};
use argus_analyzer::{
    ClaudePromptParser, ProcessTreeBuilder, PromptDriftDetector, SemanticSummarizer,
    SessionCorrelator, SessionWatcher, TelegramConfig, TriggerConfig,
};
use argus_collector::{AuditStore, SessionSummary};
use argus_common::events::AuditEvent;
use clap::{Parser, Subcommand};
use futures::StreamExt;
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

    /// Stream live session keystrokes in real-time (SSE)
    Live {
        /// Session UUID
        session_id: String,
    },

    /// Send emergency force-kill signal to terminate a remote session
    Kill {
        /// Session UUID
        session_id: String,
    },

    /// Dump all raw events of a session in JSONL
    Dump {
        /// Session UUID
        session_id: String,
    },

    /// Cryptographically verify session log integrity and tamper evidence
    Verify {
        /// Session UUID
        session_id: String,
    },

    /// Render process execution tree and sub-process lineages
    Tree {
        /// Session UUID
        session_id: String,
    },

    /// Correlate session activity, prompt drift, and build LLM semantic analysis report
    Analyze {
        /// Session UUID
        session_id: String,

        /// Optional path to Claude CLI history.jsonl
        #[arg(long)]
        claude_history: Option<PathBuf>,
    },

    /// Monitor sessions and dispatch AI-aware Telegram notifications (Idle 3m/15m, SSH Detach, Work Rollup)
    Notify {
        /// Run continuously as a background watcher daemon
        #[arg(long, default_value_t = false)]
        daemon: bool,

        /// Check interval in seconds for daemon mode (default: 15)
        #[arg(long, default_value = "15")]
        interval: u64,

        /// Dry-run mode: evaluate triggers and print notification report to stdout without sending to Telegram
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Telegram Bot Token (can also be set via ARGUS_TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN)
        #[arg(long, env = "ARGUS_TELEGRAM_BOT_TOKEN")]
        telegram_bot_token: Option<String>,

        /// Telegram Target Chat ID (can also be set via ARGUS_TELEGRAM_CHAT_ID)
        #[arg(long, env = "ARGUS_TELEGRAM_CHAT_ID", allow_hyphen_values = true)]
        telegram_chat_id: Option<String>,

        /// Telegram Topic Thread ID (optional topic thread, can also be set via ARGUS_TELEGRAM_THREAD_ID)
        #[arg(long, env = "ARGUS_TELEGRAM_THREAD_ID", allow_hyphen_values = true)]
        telegram_thread_id: Option<i64>,

        /// Idle timeout for regular shell sessions in minutes (default: 3)
        #[arg(long, default_value = "3")]
        shell_idle_mins: u64,

        /// Idle timeout for AI (Claude Code) sessions in minutes (default: 15)
        #[arg(long, default_value = "15")]
        ai_idle_mins: u64,
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
        Commands::Live { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let collector_url = cli
                .collector
                .unwrap_or_else(|| "http://127.0.0.1:19532".to_string());
            stream_live_session(&collector_url, uid).await?;
        }
        Commands::Kill { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let collector_url = cli
                .collector
                .unwrap_or_else(|| "http://127.0.0.1:19532".to_string());
            kill_session(&collector_url, uid).await?;
        }
        Commands::Dump { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let events = fetch_events(&cli.collector, &cli.db, uid).await?;
            for ev in events {
                println!("{}", serde_json::to_string(&ev)?);
            }
        }
        Commands::Verify { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            verify_session(&cli.collector, &cli.db, uid).await?;
        }
        Commands::Tree { session_id } => {
            let uid = Uuid::parse_str(&session_id).context("Invalid session UUID format")?;
            let events = fetch_events(&cli.collector, &cli.db, uid).await?;
            let execs: Vec<_> = events
                .into_iter()
                .filter_map(|e| match e {
                    AuditEvent::ProcessExec(p) => Some(p),
                    _ => None,
                })
                .collect();

            if execs.is_empty() {
                println!("No process execution events recorded for session {session_id}.");
            } else {
                let roots = ProcessTreeBuilder::build_tree(&execs);
                println!("\n=== Process Tree Lineage (Session: {session_id}) ===");
                println!("{}", ProcessTreeBuilder::render_ascii(&roots));
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

            // Prompt Drift & Injection Analysis
            if !report.ai_prompts.is_empty() {
                println!("\n### 🛡️ AI Prompt-to-Execution Drift Assessment:");
                let executed_cmds: Vec<String> = events
                    .into_iter()
                    .filter_map(|e| match e {
                        AuditEvent::ProcessExec(p) => Some(p.argv.join(" ")),
                        _ => None,
                    })
                    .collect();

                for p in &report.ai_prompts {
                    let drift = PromptDriftDetector::evaluate_drift(&p.prompt, &executed_cmds);
                    let status = if drift.is_anomalous_drift {
                        "⚠️ HIGH DRIFT / POTENTIAL INJECTION"
                    } else {
                        "✓ ALIGNED"
                    };
                    println!(
                        "  * Prompt: \"{}\" -> Status: {} (Risk: {:.2})",
                        p.prompt, status, drift.risk_score
                    );
                    for reason in &drift.reasons {
                        println!("      - {}", reason);
                    }
                }
            }
        }
        Commands::Notify {
            daemon,
            interval,
            dry_run,
            telegram_bot_token,
            telegram_chat_id,
            telegram_thread_id,
            shell_idle_mins,
            ai_idle_mins,
        } => {
            let store = AuditStore::new(&cli.db)?;
            let trigger_config = TriggerConfig::from_mins(shell_idle_mins, ai_idle_mins);

            let mut telegram_config = TelegramConfig::from_env();
            if let Some(tok) = telegram_bot_token {
                telegram_config.bot_token = Some(tok);
            }
            if let Some(cid) = telegram_chat_id {
                telegram_config.chat_id = Some(cid);
            }
            if let Some(tid) = telegram_thread_id {
                telegram_config.thread_id = Some(tid);
            }

            let watcher = SessionWatcher::new(store, trigger_config, telegram_config, dry_run);

            if daemon {
                println!("=== Starting Argus AI-Aware Session Watcher Daemon ===");
                println!("  * Polling interval: {}s", interval);
                println!("  * Shell idle threshold: {}m", shell_idle_mins);
                println!("  * AI/Claude idle threshold: {}m", ai_idle_mins);
                println!("  * Dry run: {}", dry_run);
                watcher
                    .run_daemon(Duration::from_secs(interval), None)
                    .await?;
            } else {
                println!("=== Running One-Shot AI-Aware Session Trigger Check ===");
                let reports = watcher.check_all_sessions().await?;
                if reports.is_empty() {
                    println!("No sessions triggered notifications during this check.");
                } else {
                    println!("Triggered {} notification(s):", reports.len());
                    for r in &reports {
                        println!("\n--------------------------------------------------");
                        println!("{}", r.format_telegram_markdown());
                    }
                }
            }
        }
    }

    Ok(())
}

async fn stream_live_session(collector_url: &str, session_id: Uuid) -> Result<()> {
    println!("=== Connecting to Live Session Stream (SSE): {session_id} ===");
    let client = Client::new();
    let resp = client
        .get(format!("{collector_url}/api/v1/sessions/{session_id}/live"))
        .send()
        .await?;

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        if let Ok(bytes) = chunk {
            let text = String::from_utf8_lossy(&bytes);
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    if let Ok(event) = serde_json::from_str::<AuditEvent>(data.trim()) {
                        if let AuditEvent::KeystrokeInput(k) = event {
                            print!("{}", k.as_str_lossy());
                            let _ = stdout().flush();
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn kill_session(collector_url: &str, session_id: Uuid) -> Result<()> {
    let client = Client::new();
    let resp = client
        .post(format!("{collector_url}/api/v1/sessions/{session_id}/kill"))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("Force-kill status for {session_id}:");
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

async fn verify_session(
    collector: &Option<String>,
    db_path: &PathBuf,
    session_id: Uuid,
) -> Result<()> {
    if let Some(url) = collector {
        let client = Client::new();
        let resp = client
            .get(format!("{url}/api/v1/sessions/{session_id}/verify"))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        let store = AuditStore::new(db_path)?;
        match store.verify_session_integrity(session_id) {
            Ok(_) => {
                println!("✓ Session {session_id}: Cryptographic hash chain verified. (No tampering detected)");
            }
            Err(e) => {
                println!("✗ Session {session_id}: TAMPER DETECTED! {e}");
            }
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
