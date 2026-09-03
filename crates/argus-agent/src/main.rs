use argus_agent::{EventUploader, IdentityResolver, PtyRunner};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "argus-agent",
    author,
    version,
    about = "Argus Audit Host Agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Wrap an interactive shell session with PTY audit logging
    Wrap {
        /// Shell to launch (defaults to $SHELL or /bin/bash)
        #[arg(short, long)]
        shell: Option<String>,

        /// Remote collector ingestion URL (e.g. https://audit.example.com or http://127.0.0.1:19532)
        #[arg(short, long, env = "ARGUS_COLLECTOR_URL")]
        collector: Option<String>,

        /// Local spool file path for offline buffering
        #[arg(long, env = "ARGUS_SPOOL_PATH")]
        spool: Option<PathBuf>,

        /// Automatically mask in-flight credentials (AWS, OpenAI, Private Keys) before transmission
        #[arg(long, env = "ARGUS_MASK_SECRETS", default_value_t = true)]
        mask_secrets: bool,

        /// Optional command to execute instead of interactive shell (e.g. for SSH ForceCommand)
        #[arg(last = true)]
        command: Vec<String>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Wrap {
            shell,
            collector,
            spool,
            mask_secrets,
            command,
        } => {
            let session_id = Uuid::new_v4();
            let final_command = if command.is_empty() {
                let shell_path = shell
                    .or_else(|| std::env::var("SHELL").ok())
                    .unwrap_or_else(|| "/bin/bash".to_string());
                vec![shell_path]
            } else {
                command
            };

            let (tx, rx) = channel();

            // Resolve initial identity metadata (SSH Client IP, Port, Username, Hostname)
            let init_event = IdentityResolver::resolve_current_session(session_id);

            // Spawn background async uploader thread with tokio
            let uploader = EventUploader::new(collector, spool);
            let uploader_handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(uploader.run_loop(rx));
            });

            // Run PTY foreground loop with optional in-flight secret masking
            let runner = PtyRunner::new(session_id, final_command, tx, mask_secrets);
            let exit_status = runner.run(init_event)?;

            // Wait for uploader to finish flushing remaining events
            let _ = uploader_handle.join();

            std::process::exit(exit_status);
        }
    }
}
