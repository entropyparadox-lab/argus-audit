use argus_common::events::SessionInit;
use chrono::Utc;
use std::collections::HashMap;
use std::env;
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

        SessionInit {
            session_id,
            timestamp: Utc::now(),
            hostname,
            username,
            tty,
            client_ip,
            client_port,
            ssh_key_fingerprint: None, // Filled by auth log linker if available
            ssh_key_comment: None,
            env_context: Some(env_context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_resolution() {
        let session_id = Uuid::new_v4();
        let session = IdentityResolver::resolve_current_session(session_id);

        assert_eq!(session.session_id, session_id);
        assert!(!session.hostname.is_empty());
        assert!(!session.username.is_empty());
    }
}
