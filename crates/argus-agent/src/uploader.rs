use argus_common::codec::serialize_and_compress_events;
use argus_common::events::AuditEvent;
use reqwest::Client;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use tracing::warn;

pub struct EventUploader {
    collector_url: Option<String>,
    local_spool_path: Option<PathBuf>,
    auth_token: Option<String>,
    batch_timeout: Duration,
    batch_max_size: usize,
    timeout_secs: u64,
}

impl EventUploader {
    pub fn new(collector_url: Option<String>, local_spool_path: Option<PathBuf>) -> Self {
        let auth_token = std::env::var("ARGUS_INGEST_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let timeout_secs = std::env::var("ARGUS_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(7);
        Self {
            collector_url,
            local_spool_path,
            auth_token,
            batch_timeout: Duration::from_millis(500),
            batch_max_size: 50,
            timeout_secs,
        }
    }

    /// Background worker loop consuming audit events from the channel
    pub async fn run_loop(self, rx: Receiver<AuditEvent>) {
        // Robust 7s timeout to accommodate multi-hop/Anycast CDN latency
        let client = Client::builder()
            .timeout(Duration::from_secs(self.timeout_secs))
            .connect_timeout(Duration::from_secs(4))
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
                        let _ = self.flush_batch(&client, &batch).await;
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() && last_flush.elapsed() >= self.batch_timeout {
                        let _ = self.flush_batch(&client, &batch).await;
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // Session ended: flush remaining events and exit
                    if !batch.is_empty() {
                        let _ = self.flush_batch(&client, &batch).await;
                    }
                    break;
                }
            }
        }
    }

    fn spool_to_disk(path: &PathBuf, events: &[AuditEvent]) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(jsonl) = argus_common::codec::encode_events_jsonl(events) {
                let _ = file.write_all(&jsonl);
            }
        }
    }

    async fn flush_batch(&self, client: &Client, events: &[AuditEvent]) -> bool {
        if events.is_empty() {
            return true;
        }

        // Upload to remote collector if URL is provided
        if let Some(ref url) = self.collector_url {
            match serialize_and_compress_events(events, 3) {
                Ok(compressed_bytes) => {
                    let endpoint = format!("{url}/api/v1/events");
                    let mut req = client
                        .post(&endpoint)
                        .header("Content-Type", "application/octet-stream")
                        .header("Content-Encoding", "zstd");

                    if let Some(ref token) = self.auth_token {
                        req = req.header("Authorization", format!("Bearer {token}"));
                    }

                    match req.body(compressed_bytes).send().await {
                        Ok(resp) => {
                            if resp.headers().contains_key("X-Argus-Force-Kill") {
                                warn!("⚠️ Received X-Argus-Force-Kill header from collector! Terminating session immediately.");
                                unsafe {
                                    libc::kill(0, libc::SIGKILL);
                                }
                            }
                            if resp.status().is_success() {
                                true
                            } else {
                                warn!("Collector returned non-success HTTP status: {}", resp.status());
                                if let Some(ref path) = self.local_spool_path {
                                    Self::spool_to_disk(path, events);
                                }
                                false
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to upload audit event batch to collector (fail-open): {e}"
                            );
                            if let Some(ref path) = self.local_spool_path {
                                Self::spool_to_disk(path, events);
                            }
                            false
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to compress audit events: {e}");
                    if let Some(ref path) = self.local_spool_path {
                        Self::spool_to_disk(path, events);
                    }
                    false
                }
            }
        } else if let Some(ref path) = self.local_spool_path {
            // No remote collector configured: offline spooling only
            Self::spool_to_disk(path, events);
            true
        } else {
            true
        }
    }
}
