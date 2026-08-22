use argus_common::codec::serialize_and_compress_events;
use argus_common::events::AuditEvent;
use reqwest::Client;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use tracing::{error, warn};

pub struct EventUploader {
    collector_url: Option<String>,
    local_spool_path: Option<PathBuf>,
    batch_timeout: Duration,
    batch_max_size: usize,
}

impl EventUploader {
    pub fn new(collector_url: Option<String>, local_spool_path: Option<PathBuf>) -> Self {
        Self {
            collector_url,
            local_spool_path,
            batch_timeout: Duration::from_millis(500),
            batch_max_size: 50,
        }
    }

    /// Background worker loop consuming audit events from the channel
    pub async fn run_loop(self, rx: Receiver<AuditEvent>) {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        let mut batch = Vec::new();
        let mut last_flush = std::time::Instant::now();

        loop {
            // Non-blocking try_recv or short wait
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    batch.push(event);
                    if batch.len() >= self.batch_max_size
                        || last_flush.elapsed() >= self.batch_timeout
                    {
                        self.flush_batch(&client, &batch).await;
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() && last_flush.elapsed() >= self.batch_timeout {
                        self.flush_batch(&client, &batch).await;
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // Session ended: flush remaining events and exit
                    if !batch.is_empty() {
                        self.flush_batch(&client, &batch).await;
                    }
                    break;
                }
            }
        }
    }

    async fn flush_batch(&self, client: &Client, events: &[AuditEvent]) {
        if events.is_empty() {
            return;
        }

        // 1. Spool to local file if configured
        if let Some(ref path) = self.local_spool_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                if let Ok(jsonl) = argus_common::codec::encode_events_jsonl(events) {
                    let _ = file.write_all(&jsonl);
                }
            }
        }

        // 2. Upload to remote collector if URL is provided
        if let Some(ref url) = self.collector_url {
            match serialize_and_compress_events(events, 3) {
                Ok(compressed_bytes) => {
                    let endpoint = format!("{url}/api/v1/events");
                    match client
                        .post(&endpoint)
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Encoding", "zstd")
                        .body(compressed_bytes)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if resp.headers().contains_key("X-Argus-Force-Kill") {
                                warn!("⚠️ Received X-Argus-Force-Kill header from collector! Terminating session immediately.");
                                unsafe {
                                    libc::kill(0, libc::SIGKILL);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to upload audit event batch to collector: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to compress audit events: {e}");
                }
            }
        }
    }
}
