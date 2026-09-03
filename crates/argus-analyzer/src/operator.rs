use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

pub struct OperatorRegistry;

impl OperatorRegistry {
    /// Load operator mappings from config file or environment
    fn get_mapping() -> HashMap<String, String> {
        // 1. Explicit config file from environment
        if let Ok(file_path) = env::var("ARGUS_OPERATORS_FILE") {
            if let Some(map) = Self::load_from_file(Path::new(&file_path)) {
                return map;
            }
        }

        // 2. Default user config file (~/.config/argus/operators.toml)
        if let Ok(home) = env::var("HOME") {
            let default_path = PathBuf::from(home).join(".config/argus/operators.toml");
            if default_path.exists() {
                if let Some(map) = Self::load_from_file(&default_path) {
                    return map;
                }
            }
        }

        // 3. JSON environment variable override
        if let Ok(map_json) = env::var("ARGUS_OPERATORS_MAP") {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&map_json) {
                return map
                    .into_iter()
                    .map(|(k, v)| (k.to_lowercase(), v))
                    .collect();
            }
        }

        HashMap::new()
    }

    /// Parse a simple key = "value" configuration file (TOML or Key-Value)
    fn load_from_file(path: &Path) -> Option<HashMap<String, String>> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut map = HashMap::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with('[') || trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().trim_matches('"').trim_matches('\'').to_lowercase();
                let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                if !key.is_empty() && !val.is_empty() {
                    map.insert(key, val);
                }
            }
        }
        Some(map)
    }

    /// Resolve canonical operator display name from username, comment, or fingerprint
    pub fn resolve_operator_name(
        username: &str,
        comment: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Option<String> {
        let map = Self::get_mapping();

        // 1. Match against SSH key fingerprint
        if let Some(fp) = fingerprint {
            if let Some(name) = map.get(&fp.to_lowercase()) {
                return Some(name.clone());
            }
        }

        // 2. Match against SSH key comment
        if let Some(cmt) = comment {
            let cmt_lower = cmt.to_lowercase();

            // Direct match or substring match from mapping
            if let Some(name) = map.get(&cmt_lower) {
                return Some(name.clone());
            }
            for (pattern, name) in &map {
                if cmt_lower.contains(pattern) {
                    return Some(name.clone());
                }
            }

            // Clean fallback from comment (e.g. alice@workstation -> alice)
            let trimmed = cmt.trim();
            if !trimmed.is_empty() {
                let user_part = trimmed.split('@').next().unwrap_or(trimmed);
                return Some(user_part.to_string());
            }
        }

        // 3. Fallback based on system username
        let user_lower = username.to_lowercase();
        if let Some(name) = map.get(&user_lower) {
            return Some(name.clone());
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_resolve_from_config_file() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            "[operators]\nalice = \"Alice Developer\"\nbob@workstation = \"Bob Engineer\"\n"
        )
        .unwrap();

        unsafe {
            env::set_var("ARGUS_OPERATORS_FILE", temp_file.path());
        }

        let name1 = OperatorRegistry::resolve_operator_name("alice", None, None);
        assert_eq!(name1.as_deref(), Some("Alice Developer"));

        let name2 = OperatorRegistry::resolve_operator_name("guest", Some("bob@workstation"), None);
        assert_eq!(name2.as_deref(), Some("Bob Engineer"));

        unsafe {
            env::remove_var("ARGUS_OPERATORS_FILE");
        }
    }

    #[test]
    fn test_resolve_fallback_from_comment() {
        let name = OperatorRegistry::resolve_operator_name("ubuntu", Some("charlie@node01"), None);
        assert_eq!(name.as_deref(), Some("charlie"));
    }
}
