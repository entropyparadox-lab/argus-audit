use crate::events::AuditEvent;
use anyhow::{Context, Result};
use std::io::{Read, Write};

/// Encode a batch of audit events into JSONL format
pub fn encode_events_jsonl(events: &[AuditEvent]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for event in events {
        serde_json::to_writer(&mut buf, event)
            .context("Failed to serialize audit event to JSON")?;
        buf.push(b'\n');
    }
    Ok(buf)
}

/// Decode a JSONL buffer into a vector of audit events
pub fn decode_events_jsonl(buf: &[u8]) -> Result<Vec<AuditEvent>> {
    let mut events = Vec::new();
    for line in buf.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_slice(line)
            .context("Failed to deserialize audit event from JSON line")?;
        events.push(event);
    }
    Ok(events)
}

/// Compress an arbitrary byte payload using Zstd (default level: 3 for high speed and good ratio)
pub fn compress_zstd(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), level)
        .context("Failed to initialize Zstd encoder")?;
    encoder
        .write_all(data)
        .context("Failed to write to Zstd encoder")?;
    let compressed = encoder.finish().context("Failed to finish Zstd stream")?;
    Ok(compressed)
}

/// Decompress a Zstd-compressed byte slice
pub fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder =
        zstd::stream::Decoder::new(data).context("Failed to initialize Zstd decoder")?;
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .context("Failed to read decompressed Zstd data")?;
    Ok(decompressed)
}

/// High-level helper: Serialize a batch of events and compress with Zstd
pub fn serialize_and_compress_events(events: &[AuditEvent], level: i32) -> Result<Vec<u8>> {
    let jsonl = encode_events_jsonl(events)?;
    compress_zstd(&jsonl, level)
}

/// High-level helper: Decompress a Zstd payload and deserialize into events
pub fn decompress_and_deserialize_events(compressed_data: &[u8]) -> Result<Vec<AuditEvent>> {
    let decompressed = decompress_zstd(compressed_data)?;
    decode_events_jsonl(&decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{KeystrokeInput, ProcessExec, SessionInit};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_jsonl_roundtrip() {
        let session_id = Uuid::new_v4();
        let events = vec![
            AuditEvent::SessionInit(SessionInit {
                session_id,
                timestamp: Utc::now(),
                hostname: "dev-server-01".into(),
                username: "ubuntu".into(),
                tty: "pts/1".into(),
                client_ip: Some("192.168.1.50".into()),
                client_port: Some(52341),
                ssh_key_fingerprint: Some("SHA256:abc123456789".into()),
                ssh_key_comment: Some("user_kim@company.com".into()),
                env_context: None,
            }),
            AuditEvent::KeystrokeInput(KeystrokeInput::new(
                session_id,
                1,
                120,
                b"ls -la /var/log\n".to_vec(),
                false,
            )),
            AuditEvent::ProcessExec(ProcessExec {
                session_id: Some(session_id),
                timestamp: Utc::now(),
                pid: 12345,
                ppid: 12300,
                uid: 1000,
                gid: 1000,
                comm: "ls".into(),
                argv: vec!["ls".into(), "-la".into(), "/var/log".into()],
                cwd: Some("/home/ubuntu".into()),
                exit_code: Some(0),
            }),
        ];

        let encoded = encode_events_jsonl(&events).unwrap();
        let decoded = decode_events_jsonl(&encoded).unwrap();

        assert_eq!(events.len(), decoded.len());
        assert_eq!(events[0], decoded[0]);
        assert_eq!(events[1], decoded[1]);
        assert_eq!(events[2], decoded[2]);
    }

    #[test]
    fn test_zstd_compression_roundtrip() {
        let session_id = Uuid::new_v4();
        let mut events = Vec::new();
        // Generate 100 events to simulate a session
        for i in 0..100 {
            events.push(AuditEvent::KeystrokeInput(KeystrokeInput::new(
                session_id,
                i,
                i * 50,
                format!("echo 'Testing keystroke {i}'\n").into_bytes(),
                false,
            )));
        }

        let compressed = serialize_and_compress_events(&events, 3).unwrap();
        let raw_jsonl = encode_events_jsonl(&events).unwrap();

        println!(
            "Raw JSONL size: {} bytes, Zstd size: {} bytes (Ratio: {:.2}%)",
            raw_jsonl.len(),
            compressed.len(),
            (compressed.len() as f64 / raw_jsonl.len() as f64) * 100.0
        );

        // Zstd should achieve significant compression on repetitive text events
        assert!(compressed.len() < raw_jsonl.len());

        let decompressed = decompress_and_deserialize_events(&compressed).unwrap();
        assert_eq!(events.len(), decompressed.len());
        assert_eq!(events[0], decompressed[0]);
    }
}
