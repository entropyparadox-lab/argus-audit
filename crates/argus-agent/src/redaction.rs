use regex::Regex;
use std::sync::LazyLock;

static AWS_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
static PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});
static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}").unwrap());
static AI_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sk-(proj|ant)-[0-9a-zA-Z_-]{20,}").unwrap());

pub struct SecretRedactor;

impl SecretRedactor {
    /// Mask known credentials and private keys from raw input bytes
    pub fn redact_bytes(input: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(input) else {
            return input.to_vec();
        };

        let masked = Self::redact_str(text);
        masked.into_bytes()
    }

    /// Redact known secrets from a UTF-8 string
    pub fn redact_str(text: &str) -> String {
        let step1 = AWS_KEY_REGEX.replace_all(text, "[REDACTED:AWS_KEY]");
        let step2 = PRIVATE_KEY_REGEX.replace_all(&step1, "[REDACTED:PRIVATE_KEY]");
        let step3 = GITHUB_TOKEN_REGEX.replace_all(&step2, "[REDACTED:GITHUB_TOKEN]");
        let step4 = AI_KEY_REGEX.replace_all(&step3, "[REDACTED:AI_API_KEY]");
        step4.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_aws_key() {
        let input = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE1\n";
        let redacted = SecretRedactor::redact_str(input);
        assert_eq!(redacted, "export AWS_ACCESS_KEY_ID=[REDACTED:AWS_KEY]1\n");
    }

    #[test]
    fn test_redact_private_key_block() {
        let input = "ssh-add << 'EOF'\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n-----END OPENSSH PRIVATE KEY-----\nEOF\n";
        let redacted = SecretRedactor::redact_str(input);
        assert_eq!(redacted, "ssh-add << 'EOF'\n[REDACTED:PRIVATE_KEY]\nEOF\n");
    }

    #[test]
    fn test_redact_ai_keys() {
        let input = "OPENAI_API_KEY=sk-proj-abc1234567890abcdef1234567890\nANTHROPIC_API_KEY=sk-ant-api03-abcdef123456789012345\n";
        let redacted = SecretRedactor::redact_str(input);
        assert_eq!(
            redacted,
            "OPENAI_API_KEY=[REDACTED:AI_API_KEY]\nANTHROPIC_API_KEY=[REDACTED:AI_API_KEY]\n"
        );
    }
}
