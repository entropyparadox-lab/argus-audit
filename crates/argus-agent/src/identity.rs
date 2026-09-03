use argus_common::events::SessionInit;
use argus_common::ssh::{
    compute_ssh_fingerprint, parse_auth_info, parse_authorized_keys, ParsedSshKey,
};
use chrono::Utc;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct IdentityResolver;

impl IdentityResolver {
    /// Resolve the current interactive user and SSH connection context
    pub fn resolve_current_session(session_id: Uuid) -> SessionInit {
        let hostname = nix::unistd::gethostname()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown-host".to_string());

        let username = env::var("USER")
            .or_else(|_| env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let tty = env::var("SSH_TTY").unwrap_or_else(|_| "/dev/tty".to_string());

        let mut client_ip = None;
        let mut client_port = None;

        // Parse SSH_CLIENT format: "192.168.1.50 52341 22"
        if let Ok(ssh_client) = env::var("SSH_CLIENT") {
            let parts: Vec<&str> = ssh_client.split_whitespace().collect();
            if !parts.is_empty() {
                client_ip = Some(parts[0].to_string());
            }
            if parts.len() >= 2 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    client_port = Some(port);
                }
            }
        } else if let Ok(ssh_conn) = env::var("SSH_CONNECTION") {
            // Fallback: SSH_CONNECTION format: "192.168.1.50 52341 10.0.0.1 22"
            let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
            if !parts.is_empty() {
                client_ip = Some(parts[0].to_string());
            }
            if parts.len() >= 2 {
                if let Ok(port) = parts[1].parse::<u16>() {
                    client_port = Some(port);
                }
            }
        }

        // Capture non-sensitive diagnostic environment variables
        let mut env_context = HashMap::new();
        for key in &["SHELL", "TERM", "SSH_AUTH_SOCK", "LANG", "PWD"] {
            if let Ok(val) = env::var(key) {
                env_context.insert(key.to_string(), val);
            }
        }

        // Resolve SSH key identity (Fingerprint & Comment/Memo)
        let (ssh_key_fingerprint, ssh_key_comment) = Self::resolve_ssh_key_identity();

        SessionInit {
            session_id,
            timestamp: Utc::now(),
            hostname,
            username,
            tty,
            client_ip,
            client_port,
            ssh_key_fingerprint,
            ssh_key_comment,
            env_context: Some(env_context),
        }
    }

    /// Resolve SSH public key fingerprint and human comment from OpenSSH environment or auth files
    pub fn resolve_ssh_key_identity() -> (Option<String>, Option<String>) {
        let auth_info_path = env::var("SSH_USER_AUTH").ok();
        let home_dir = env::var("HOME").ok().map(PathBuf::from);

        Self::resolve_ssh_key_identity_with_paths(
            auth_info_path.as_deref().map(Path::new),
            home_dir.as_deref(),
        )
    }

    /// Internal resolver with explicit paths for zero-overhead execution and testability
    pub fn resolve_ssh_key_identity_with_paths(
        auth_info_path: Option<&Path>,
        home_dir: Option<&Path>,
    ) -> (Option<String>, Option<String>) {
        let mut resolved_fingerprint = None;
        let mut resolved_comment = None;

        // 1. Primary: OpenSSH ExposeAuthInfo ($SSH_USER_AUTH)
        if let Some(auth_path) = auth_info_path {
            if let Ok(content) = fs::read_to_string(auth_path) {
                let auth_entries = parse_auth_info(&content);
                for (_key_type, b64_blob) in auth_entries {
                    if let Some(fp) = compute_ssh_fingerprint(&b64_blob) {
                        resolved_fingerprint = Some(fp.clone());

                        // Match against authorized_keys to find matching comment
                        if let Some(home) = home_dir {
                            let keys = Self::load_authorized_keys_from_dir(home);
                            for k in keys {
                                if k.b64_blob == b64_blob || k.fingerprint == fp {
                                    if let Some(c) = k.comment {
                                        resolved_comment = Some(c);
                                        break;
                                    }
                                }
                            }
                        }
                        if resolved_fingerprint.is_some() {
                            break;
                        }
                    }
                }
            }
        }

        // 2. Secondary fallback: Explicit environment variables (if set by PAM or authorized_keys environment=)
        if resolved_fingerprint.is_none() {
            if let Ok(fp) = env::var("SSH_KEY_FINGERPRINT") {
                if !fp.trim().is_empty() {
                    resolved_fingerprint = Some(fp.trim().to_string());
                }
            }
        }
        if resolved_comment.is_none() {
            if let Ok(cmt) = env::var("SSH_KEY_COMMENT") {
                if !cmt.trim().is_empty() {
                    resolved_comment = Some(cmt.trim().to_string());
                }
            }
        }

        // 3. Tertiary fallback: If authorized_keys has exactly 1 valid key on single-tenant host
        if resolved_fingerprint.is_none() && resolved_comment.is_none() {
            if let Some(home) = home_dir {
                let keys = Self::load_authorized_keys_from_dir(home);
                if keys.len() == 1 {
                    let single_key = &keys[0];
                    resolved_fingerprint = Some(single_key.fingerprint.clone());
                    resolved_comment = single_key.comment.clone();
                }
            }
        }

        (resolved_fingerprint, resolved_comment)
    }

    /// Helper to load parsed keys from ~/.ssh/authorized_keys and ~/.ssh/authorized_keys2
    fn load_authorized_keys_from_dir(home_dir: &Path) -> Vec<ParsedSshKey> {
        let mut result = Vec::new();
        let ssh_dir = home_dir.join(".ssh");

        let auth_keys_path = ssh_dir.join("authorized_keys");
        if let Ok(content) = fs::read_to_string(&auth_keys_path) {
            result.extend(parse_authorized_keys(&content));
        }

        let auth_keys2_path = ssh_dir.join("authorized_keys2");
        if let Ok(content) = fs::read_to_string(&auth_keys2_path) {
            result.extend(parse_authorized_keys(&content));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_identity_resolution() {
        let session_id = Uuid::new_v4();
        let session = IdentityResolver::resolve_current_session(session_id);

        assert_eq!(session.session_id, session_id);
        assert!(!session.hostname.is_empty());
        assert!(!session.username.is_empty());
    }

    #[test]
    fn test_resolve_ssh_key_with_auth_info_and_authorized_keys() {
        let temp_dir = tempdir().unwrap();
        let home_dir = temp_dir.path().join("home_user");
        let ssh_dir = home_dir.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();

        let pub_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA";
        let auth_keys_content = format!("ssh-ed25519 {} security@entropyparadox.com\n", pub_blob);
        fs::write(ssh_dir.join("authorized_keys"), auth_keys_content).unwrap();

        let auth_info_file = temp_dir.path().join("auth_info");
        let auth_info_content = format!("publickey ssh-ed25519 {}\n", pub_blob);
        fs::write(&auth_info_file, auth_info_content).unwrap();

        let (fp, comment) = IdentityResolver::resolve_ssh_key_identity_with_paths(
            Some(&auth_info_file),
            Some(&home_dir),
        );

        assert!(fp.is_some());
        assert!(fp.unwrap().starts_with("SHA256:"));
        assert_eq!(comment.as_deref(), Some("security@entropyparadox.com"));
    }

    #[test]
    fn test_resolve_single_key_fallback() {
        let temp_dir = tempdir().unwrap();
        let home_dir = temp_dir.path().join("home_user");
        let ssh_dir = home_dir.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();

        let pub_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAGP15qR4B0l5w/Fz5G4YhXhV7zX7Fz1Z9tT8rG9p1bA";
        let auth_keys_content = format!("ssh-ed25519 {} operator@workstation\n", pub_blob);
        fs::write(ssh_dir.join("authorized_keys"), auth_keys_content).unwrap();

        // No auth_info provided -> single key fallback
        let (fp, comment) =
            IdentityResolver::resolve_ssh_key_identity_with_paths(None, Some(&home_dir));

        assert!(fp.is_some());
        assert_eq!(comment.as_deref(), Some("operator@workstation"));
    }
}
