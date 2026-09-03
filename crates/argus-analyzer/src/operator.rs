use std::collections::HashMap;
use std::env;

pub struct OperatorRegistry;

impl OperatorRegistry {
    /// Resolve canonical operator display name from username, comment, or fingerprint
    pub fn resolve_operator_name(
        username: &str,
        comment: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Option<String> {
        // 1. Dynamic override from environment variable (JSON string)
        if let Ok(map_json) = env::var("ARGUS_OPERATORS_MAP") {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&map_json) {
                if let Some(fp) = fingerprint {
                    if let Some(name) = map.get(fp) {
                        return Some(name.clone());
                    }
                }
                if let Some(cmt) = comment {
                    if let Some(name) = map.get(cmt) {
                        return Some(name.clone());
                    }
                }
                if let Some(name) = map.get(username) {
                    return Some(name.clone());
                }
            }
        }

        // 2. Built-in Core Team Knowledge Mapping
        if let Some(cmt) = comment {
            let lower = cmt.to_lowercase();
            if lower.contains("charles") || lower.contains("cycorld") || cmt.contains("최용철") {
                return Some("최용철".to_string());
            } else if lower.contains("juchan")
                || lower.contains("chan@")
                || lower.contains("chansui")
            {
                return Some("임주찬".to_string());
            } else if lower.contains("hosung") || lower.contains("songhoseong") {
                return Some("송호성".to_string());
            } else if lower.contains("itlockit")
                || lower.contains("sungho")
                || lower.contains("seongho")
                || cmt.contains("윤성호")
            {
                return Some("윤성호".to_string());
            } else if lower.contains("vodana") {
                return Some("vodana".to_string());
            } else if lower.contains("dongjae") {
                return Some("이동재".to_string());
            } else if lower.contains("hyungsuk") {
                return Some("최형석".to_string());
            } else if lower.contains("bluesh55") || lower.contains("seunghwan") {
                return Some("오승환".to_string());
            } else if lower.contains("jisoo") {
                return Some("이지수".to_string());
            } else if lower.contains("mingyeong") || lower.contains("mingyeoc") {
                return Some("민경문".to_string());
            } else if lower.contains("hoeyun") {
                return Some("회윤".to_string());
            } else if lower.contains("soone") {
                return Some("soone".to_string());
            }

            // Clean fallback from comment (e.g. user@host -> user)
            let trimmed = cmt.trim();
            if !trimmed.is_empty() {
                let user_part = trimmed.split('@').next().unwrap_or(trimmed);
                return Some(user_part.to_string());
            }
        }

        // 3. Fallback based on username if explicit team member account (ONLY when comment is None)
        let user_lower = username.to_lowercase();
        if user_lower == "cycorld" || user_lower == "charles" {
            Some("최용철".to_string())
        } else if user_lower == "juchan" {
            Some("임주찬".to_string())
        } else if user_lower == "hosung" {
            Some("송호성".to_string())
        } else if user_lower == "sungho" || user_lower == "seongho" {
            Some("윤성호".to_string())
        } else if user_lower == "vodana" {
            Some("vodana".to_string())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_from_comment() {
        let name =
            OperatorRegistry::resolve_operator_name("ubuntu", Some("charles@cycorld.com"), None);
        assert_eq!(name.as_deref(), Some("최용철"));

        let name2 = OperatorRegistry::resolve_operator_name(
            "vodana",
            Some("juchan@entropyparadox.com"),
            None,
        );
        assert_eq!(name2.as_deref(), Some("임주찬"));
    }

    #[test]
    fn test_resolve_from_username() {
        let name = OperatorRegistry::resolve_operator_name("cycorld", None, None);
        assert_eq!(name.as_deref(), Some("최용철"));

        let name2 = OperatorRegistry::resolve_operator_name("vodana", None, None);
        assert_eq!(name2.as_deref(), Some("vodana"));

        let name3 = OperatorRegistry::resolve_operator_name("hosung", None, None);
        assert_eq!(name3.as_deref(), Some("송호성"));

        let name4 = OperatorRegistry::resolve_operator_name("juchan", None, None);
        assert_eq!(name4.as_deref(), Some("임주찬"));
    }
}
