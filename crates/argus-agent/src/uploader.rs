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
    auth_token: Option<String>,
    batch_timeout: Duration,
    batch_max_size: usize,
}

impl EventUploader {
    pub fn new(collector_url: Option<String>, local_spool_path: Option<PathBuf>) -> Self {
        let auth_token = std::env::var("ARGUS_INGEST_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        Self {
            collector_url,
            local_spool_path,
            auth_token,
            batch_timeout: Duration::from_millis(500),
            batch_max_size: 50,
        }
    }

    /// Background worker loop consuming audit events from the channel
    pub async fn run_loop(self, rx: Receiver<AuditEvent>) {
        // Short 2s network timeout so developer session exits are never blocked
        let client = Client::builder()
            .timeout(Duration::from_millis(2000))
            .build()
            .unwrap_or_default();

        let mut batch = Vec::new();
        let mut last_flush = std::time::Instant::now();
        let mut consecutive_upload_errors = 0usize;

        loop {
            // Non-blocking try_recv or short wait
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    batch.push(event);
                    if batch.len() >= self.batch_max_size
                        || last_flush.elapsed() >= self.batch_timeout
                    {
                        let ok = self.flush_batch(&client, &batch).await;
                        if ok {
                            consecutive_upload_errors = 0;
                        } else {
                            consecutive_upload_errors += 1;
                        }
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() && last_flush.elapsed() >= self.batch_timeout {
                        let ok = self.flush_batch(&client, &batch).await;
                        if ok {
                            consecutive_upload_errors = 0;
                        } else {
                            consecutive_upload_errors += 1;
                        }
                        batch.clear();
                        last_flush = std::time::Instant::now();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // Session ended: flush remaining events and exit
                    if !batch.is_empty() {
                        // Fail-open: if collector is offline, skip remote upload retry to avoid delaying developer terminal exit
                        if consecutive_upload_errors < 2 {
                            let _ = self.flush_batch(&client, &batch).await;
                        } else if let Some(ref path) = self.local_spool_path {
                            Self::spool_to_disk(path, &batch);
                        }
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

        // 1. Spool to local file if configured (offline persistence)
        if let Some(ref path) = self.local_spool_path {
            Self::spool_to_disk(path, events);
        }

        // 2. Upload to remote collector if URL is provided
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
                            true
                        }
                        Err(e) => {
                            error!(
                                "Failed to upload audit event batch to collector (fail-open): {e}"
                            );
                            false
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to compress audit events: {e}");
                    false
                }
            }
        } else {
            true
        }
    }
}
