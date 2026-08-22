use argus_collector::{AuditStore, CollectorServer};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "argus-collector",
    author,
    version,
    about = "Argus Audit Ingestion Collector"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the audit log ingestion HTTP/2 server
    Run {
        /// Bind address (e.g. 0.0.0.0:19532 or 127.0.0.1:19532)
        #[arg(short, long, default_value = "0.0.0.0:19532", env = "ARGUS_BIND_ADDR")]
        bind: SocketAddr,

        /// Path to SQLite audit database
        #[arg(long, default_value = "audit.db", env = "ARGUS_DB_PATH")]
        db: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { bind, db } => {
            let store = AuditStore::new(&db)?;
            let server = CollectorServer::new(store, bind);
            server.run().await?;
        }
    }

    Ok(())
}
