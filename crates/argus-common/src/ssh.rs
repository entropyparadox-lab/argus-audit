use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parsed SSH Public Key information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSshKey {
    pub key_type: String,
    pub b64_blob: String,
    pub fingerprint: String,
    pub comment: Option<String>,
}

/// Compute standard OpenSSH SHA256 fingerprint from base64 encoded public key blob
pub fn compute_ssh_fingerprint(b64_blob: &str) -> Option<String> {
    let trimmed = b64_blob.trim();
    if trimmed.is_empty() {
        return None;
    }
    let decoded = BASE64_STANDARD.decode(trimmed).ok()?;
    let hash = Sha256::digest(&decoded);
    let b64_hash = BASE64_STANDARD.encode(hash);
    Some(format!("SHA256:{}", b64_hash.trim_end_matches('=')))
}

/// Check if a token is a known OpenSSH key type
pub fn is_known_key_type(s: &str) -> bool {
    s.starts_with("ssh-")
        || s.starts_with("ecdsa-")
        || s.starts_with("sk-ssh-")
        || s.starts_with("sk-ecdsa-")
}

/// Parse a single line from an authorized_keys file
pub fn parse_authorized_keys_line(line: &str) -> Option<ParsedSshKey> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let key_type_idx = tokens.iter().position(|&t| is_known_key_type(t))?;
    if key_type_idx + 1 >= tokens.len() {
        return None;
    }

    let key_type = tokens[key_type_idx].to_string();
    let b64_blob = tokens[key_type_idx + 1].to_string();
    let fingerprint = compute_ssh_fingerprint(&b64_blob)?;

    let comment = if key_type_idx + 2 < tokens.len() {
        let comment_str = tokens[key_type_idx + 2..].join(" ").trim().to_string();
        if comment_str.is_empty() {
            None
        } else {
            Some(comment_str)
        }
    } else {
        None
    };

    Some(ParsedSshKey {
        key_type,
        b64_blob,
        fingerprint,
        comment,
    })
}

/// Parse full content of authorized_keys file
pub fn parse_authorized_keys(content: &str) -> Vec<ParsedSshKey> {
    content
        .lines()
        .filter_map(parse_authorized_keys_line)
        .collect()
}

/// Parse a single line from OpenSSH auth_info file ($SSH_USER_AUTH)
///
/// Format written by OpenSSH sshd:
/// "publickey <key-type> <base64-blob>" or "<key-type> <base64-blob>"
pub fn parse_auth_info_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    if (tokens[0] == "publickey" || tokens[0] == "publickey-cert" || tokens[0] == "key")
        && tokens.len() >= 3
    {
        Some((tokens[1].to_string(), tokens[2].to_string()))
    } else if is_known_key_type(tokens[0]) && tokens.len() >= 2 {
        Some((tokens[0].to_string(), tokens[1].to_string()))
    } else {
        None
    }
}

/// Parse full content of OpenSSH auth_info file ($SSH_USER_AUTH)
pub fn parse_auth_info(content: &str) -> Vec<(String, String)> {
    content.lines().filter_map(parse_auth_info_line).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_ssh_fingerprint_ed25519() {
        // Standard Ed25519 pubkey blob
        let b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA";
        let fp = compute_ssh_fingerprint(b64);
        assert!(fp.is_some());
        assert!(fp.unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn test_parse_authorized_keys_line_simple() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA charles@cycorld.com";
        let parsed = parse_authorized_keys_line(line).expect("must parse");
        assert_eq!(parsed.key_type, "ssh-ed25519");
        assert_eq!(
            parsed.b64_blob,
            "AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA"
        );
        assert_eq!(parsed.comment.as_deref(), Some("charles@cycorld.com"));
        assert!(parsed.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_parse_authorized_keys_line_with_options() {
        let line = "no-port-forwarding,no-agent-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3 test_user@company";
        let parsed = parse_authorized_keys_line(line).expect("must parse");
        assert_eq!(parsed.key_type, "ssh-rsa");
        assert_eq!(parsed.comment.as_deref(), Some("test_user@company"));
    }

    #[test]
    fn test_parse_auth_info() {
        let auth_content = "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA\n";
        let entries = parse_auth_info(auth_content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "ssh-ed25519");
        assert_eq!(
            entries[0].1,
            "AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA"
        );
    }
}
