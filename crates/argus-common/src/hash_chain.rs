use crate::events::AuditEvent;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainedAuditEvent {
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    pub event: AuditEvent,
}

impl ChainedAuditEvent {
    /// Create a new chained audit event with cryptographic hash
    pub fn new(seq: u64, prev_hash: &str, event: AuditEvent) -> Self {
        let hash = compute_event_hash(seq, prev_hash, &event);
        Self {
            seq,
            prev_hash: prev_hash.to_string(),
            hash,
            event,
        }
    }

    /// Verify this individual event's hash
    pub fn verify_hash(&self) -> bool {
        let expected = compute_event_hash(self.seq, &self.prev_hash, &self.event);
        self.hash == expected
    }
}

/// Deterministically compute SHA256 hash of (seq + prev_hash + event_json)
pub fn compute_event_hash(seq: u64, prev_hash: &str, event: &AuditEvent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(prev_hash.as_bytes());
    if let Ok(json) = serde_json::to_vec(event) {
        hasher.update(&json);
    }
    hex::encode(hasher.finalize())
}

/// Verify an entire sequence of chained audit events for mathematical tamper evidence
pub fn verify_event_chain(chain: &[ChainedAuditEvent]) -> Result<()> {
    if chain.is_empty() {
        return Ok(());
    }

    let mut expected_prev_hash = chain[0].prev_hash.clone();

    for (idx, item) in chain.iter().enumerate() {
        // 1. Verify sequence order
        if idx > 0 && item.seq != chain[idx - 1].seq + 1 {
            bail!(
                "Sequence discontinuity detected at index {}: expected seq {}, found {}",
                idx,
                chain[idx - 1].seq + 1,
                item.seq
            );
        }

        // 2. Verify prev_hash linkage
        if item.prev_hash != expected_prev_hash {
            bail!(
                "Tamper detected: Hash chain broken at seq {}. Expected prev_hash {}, found {}",
                item.seq,
                expected_prev_hash,
                item.prev_hash
            );
        }

        // 3. Verify event payload hash
        if !item.verify_hash() {
            bail!(
                "Tamper detected: Payload hash mismatch at seq {}. Event content was altered.",
                item.seq
            );
        }

        expected_prev_hash = item.hash.clone();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{KeystrokeInput, SessionInit};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_valid_hash_chain() {
        let session_id = Uuid::new_v4();
        let ev1 = AuditEvent::SessionInit(SessionInit {
            session_id,
            timestamp: Utc::now(),
            hostname: "host1".into(),
            username: "user1".into(),
            tty: "pts/1".into(),
            client_ip: Some("1.2.3.4".into()),
            client_port: Some(22),
            ssh_key_fingerprint: None,
            ssh_key_comment: None,
            env_context: None,
        });
        let ev2 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            50,
            b"echo hi\n".to_vec(),
            false,
        ));

        let c1 = ChainedAuditEvent::new(1, GENESIS_HASH, ev1);
        let c2 = ChainedAuditEvent::new(2, &c1.hash, ev2);

        let chain = vec![c1, c2];
        assert!(verify_event_chain(&chain).is_ok());
    }

    #[test]
    fn test_tampered_payload_detection() {
        let session_id = Uuid::new_v4();
        let ev1 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            50,
            b"rm -rf /tmp\n".to_vec(),
            false,
        ));
        let mut c1 = ChainedAuditEvent::new(1, GENESIS_HASH, ev1);

        // Attacker alters payload to hide command
        c1.event = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            50,
            b"ls -la\n".to_vec(),
            false,
        ));

        assert!(verify_event_chain(&[c1]).is_err());
    }

    #[test]
    fn test_deleted_event_detection() {
        let session_id = Uuid::new_v4();
        let ev1 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            1,
            50,
            b"cmd1\n".to_vec(),
            false,
        ));
        let ev2 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            2,
            100,
            b"malicious_cmd\n".to_vec(),
            false,
        ));
        let ev3 = AuditEvent::KeystrokeInput(KeystrokeInput::new(
            session_id,
            3,
            150,
            b"cmd3\n".to_vec(),
            false,
        ));

        let c1 = ChainedAuditEvent::new(1, GENESIS_HASH, ev1);
        let c2 = ChainedAuditEvent::new(2, &c1.hash, ev2);
        let c3 = ChainedAuditEvent::new(3, &c2.hash, ev3);

        // Attacker deletes c2 from database
        let tampered_chain = vec![c1, c3];
        assert!(verify_event_chain(&tampered_chain).is_err());
    }
}
