use regex::Regex;
use std::sync::LazyLock;

// 1. Cloud Provider & Dedicated Service Credentials
static AWS_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
static PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});
static GITHUB_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh[pousr]_[0-9a-zA-Z]{36,}|github_pat_[0-9a-zA-Z_]{82}").unwrap()
});

// Dedicated LLM & AI Service API Keys (Gitleaks Standard Patterns)
static ANTHROPIC_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk-ant-(?:api03-|admin01-)?[a-zA-Z0-9_-]{20,})\b").unwrap());
static OPENAI_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(sk-(?:proj-|svcacct-|admin-)[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{32,51})\b")
        .unwrap()
});
static GEMINI_GCP_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(AIza[0-9A-Za-z_-]{35})\b").unwrap());
static HUGGINGFACE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(hf_[a-zA-Z0-9]{34,}|api_org_[a-zA-Z0-9]{34,})\b").unwrap());
static GROQ_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(gsk_[a-zA-Z0-9]{48,})\b").unwrap());
static REPLICATE_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(r8_[a-zA-Z0-9]{32,})\b").unwrap());
static OPENROUTER_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk-or-v1-[a-f0-9]{64})\b").unwrap());
static PERPLEXITY_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(pplx-[a-zA-Z0-9]{48})\b").unwrap());
static DEEPSEEK_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(sk-[a-f0-9]{32})\b").unwrap());

static SLACK_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap());
static NPM_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"npm_[0-9a-zA-Z]{36}").unwrap());
static JWT_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[0-9a-zA-Z_-]{10,}\.eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}").unwrap()
});

// 2. Embedded URL Credentials (e.g. postgres://user:password@host:5432/db)
static URL_CREDENTIALS_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^@\s/]*:)([^@\s/]+)(@[^\s/]+)").unwrap()
});

// 3. Inline CLI Argument Passwords
static MYSQL_CLI_PW_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|\s)(-p)([^-\s"'`;|&><][^\s"'`;|&><]*)"#).unwrap());
static MYSQL_LONG_PW_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|\s)(--password=)([^\s"'`;|&><]+)"#).unwrap());
static REDIS_AUTH_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|\s)(-a\s+|--auth\s+|--auth=)([^\s"'`;|&><]+)"#).unwrap());
static CURL_USER_PW_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(^|\s)(-u\s+|--user\s+)(["']?[^:\s"'/]+):([^/\s"'][^\s"']*)(["']?)"#).unwrap()
});
static SSHPASS_PW_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)(^|\s)(sshpass\s+-p\s*)([^\s"'`;|&><]+)"#).unwrap());
static BEARER_AUTH_HEADER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(bearer\s+)([0-9a-zA-Z_.-]{20,})").unwrap());

// 4. General .env & Shell Export Secret Assignments
static ENV_SECRET_ASSIGN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(^|\s)(export\s+)?([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|AUTH_KEY|PRIVATE_KEY|APIKEY|API_KEY)[A-Z0-9_]*\s*=\s*)(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[^\s"'`;|&><]{8,})"#,
    )
    .unwrap()
});

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
        // 1. Dedicated token patterns
        let step1 = AWS_KEY_REGEX.replace_all(text, "[REDACTED:AWS_KEY]");
        let step2 = PRIVATE_KEY_REGEX.replace_all(&step1, "[REDACTED:PRIVATE_KEY]");
        let step3 = GITHUB_TOKEN_REGEX.replace_all(&step2, "[REDACTED:GITHUB_TOKEN]");
        let step4_1 = ANTHROPIC_KEY_REGEX.replace_all(&step3, "[REDACTED:ANTHROPIC_KEY]");
        let step4_2 = OPENAI_KEY_REGEX.replace_all(&step4_1, "[REDACTED:OPENAI_KEY]");
        let step4_3 = GEMINI_GCP_KEY_REGEX.replace_all(&step4_2, "[REDACTED:GEMINI_KEY]");
        let step4_4 = HUGGINGFACE_KEY_REGEX.replace_all(&step4_3, "[REDACTED:HUGGINGFACE_TOKEN]");
        let step4_5 = GROQ_KEY_REGEX.replace_all(&step4_4, "[REDACTED:GROQ_KEY]");
        let step4_6 = REPLICATE_KEY_REGEX.replace_all(&step4_5, "[REDACTED:REPLICATE_KEY]");
        let step4_7 = OPENROUTER_KEY_REGEX.replace_all(&step4_6, "[REDACTED:OPENROUTER_KEY]");
        let step4_8 = PERPLEXITY_KEY_REGEX.replace_all(&step4_7, "[REDACTED:PERPLEXITY_KEY]");
        let step4_9 = DEEPSEEK_KEY_REGEX.replace_all(&step4_8, "[REDACTED:DEEPSEEK_KEY]");
        let step5 = SLACK_TOKEN_REGEX.replace_all(&step4_9, "[REDACTED:SLACK_TOKEN]");
        let step6 = NPM_TOKEN_REGEX.replace_all(&step5, "[REDACTED:NPM_TOKEN]");
        let step7 = JWT_TOKEN_REGEX.replace_all(&step6, "[REDACTED:JWT]");

        // 2. URL Embedded Credentials
        let step8 = URL_CREDENTIALS_REGEX.replace_all(&step7, "${1}[REDACTED:PASSWORD]${3}");

        // 3. Inline CLI Arguments
        let step9 = MYSQL_CLI_PW_REGEX.replace_all(&step8, "${1}${2}[REDACTED:PASSWORD]");
        let step10 = MYSQL_LONG_PW_REGEX.replace_all(&step9, "${1}${2}[REDACTED:PASSWORD]");
        let step11 = REDIS_AUTH_REGEX.replace_all(&step10, "${1}${2}[REDACTED:PASSWORD]");
        let step12 =
            CURL_USER_PW_REGEX.replace_all(&step11, "${1}${2}${3}:[REDACTED:PASSWORD]${5}");
        let step13 = SSHPASS_PW_REGEX.replace_all(&step12, "${1}${2}[REDACTED:PASSWORD]");
        let step14 = BEARER_AUTH_HEADER_REGEX.replace_all(&step13, "${1}[REDACTED:BEARER_TOKEN]");

        // 4. .env and Export Assignments
        let step15 = ENV_SECRET_ASSIGN_REGEX.replace_all(&step14, "${1}${2}${3}[REDACTED:SECRET]");

        step15.into_owned()
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
        let input = "ssh-add << 'EOF'\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret_bytes_here\n-----END OPENSSH PRIVATE KEY-----\nEOF\n";
        let redacted = SecretRedactor::redact_str(input);
        assert_eq!(redacted, "ssh-add << 'EOF'\n[REDACTED:PRIVATE_KEY]\nEOF\n");
    }

    #[test]
    fn test_redact_ai_and_github_keys() {
        let input = "openai: sk-proj-1234567890abcdefghijklmn\nanthropic: sk-ant-api03-1234567890abcdefghijklmnAA\ngemini: AIzaSyD1234567890abcdefghijklmnopq12345\ngroq: gsk_123456789012345678901234567890123456789012345678\ngithub: ghp_123456789012345678901234567890123456\n";
        let redacted = SecretRedactor::redact_str(input);
        assert!(redacted.contains("[REDACTED:OPENAI_KEY]"));
        assert!(redacted.contains("[REDACTED:ANTHROPIC_KEY]"));
        assert!(redacted.contains("[REDACTED:GEMINI_KEY]"));
        assert!(redacted.contains("[REDACTED:GROQ_KEY]"));
        assert!(redacted.contains("[REDACTED:GITHUB_TOKEN]"));
    }

    #[test]
    fn test_redact_url_passwords() {
        let input1 = "DATABASE_URL=postgres://appuser:secretpass123@db.internal:5432/production\n";
        let redacted1 = SecretRedactor::redact_str(input1);
        assert_eq!(
            redacted1,
            "DATABASE_URL=postgres://appuser:[REDACTED:PASSWORD]@db.internal:5432/production\n"
        );

        let input2 = "redis-cli -u redis://:supersecretauth@10.0.0.5:6379\n";
        let redacted2 = SecretRedactor::redact_str(input2);
        assert_eq!(
            redacted2,
            "redis-cli -u redis://:[REDACTED:PASSWORD]@10.0.0.5:6379\n"
        );
    }

    #[test]
    fn test_redact_inline_cli_args() {
        // mysql -pPassword
        let input1 = "mysql -u root -pRootSecretPassword123 -h localhost\n";
        let redacted1 = SecretRedactor::redact_str(input1);
        assert_eq!(
            redacted1,
            "mysql -u root -p[REDACTED:PASSWORD] -h localhost\n"
        );

        // mysql --password=Password
        let input2 = "mysql --user=root --password=SuperSecretPassword app_db\n";
        let redacted2 = SecretRedactor::redact_str(input2);
        assert_eq!(
            redacted2,
            "mysql --user=root --password=[REDACTED:PASSWORD] app_db\n"
        );

        // redis-cli -a Password
        let input3 = "redis-cli -h 127.0.0.1 -a MyRedisPassword ping\n";
        let redacted3 = SecretRedactor::redact_str(input3);
        assert_eq!(
            redacted3,
            "redis-cli -h 127.0.0.1 -a [REDACTED:PASSWORD] ping\n"
        );

        // curl -u user:pass
        let input4 = "curl -u admin:SecretPassword123 https://api.internal/health\n";
        let redacted4 = SecretRedactor::redact_str(input4);
        assert_eq!(
            redacted4,
            "curl -u admin:[REDACTED:PASSWORD] https://api.internal/health\n"
        );

        // sshpass -p Password
        let input5 = "sshpass -p MySSHPassword ssh dev@server\n";
        let redacted5 = SecretRedactor::redact_str(input5);
        assert_eq!(redacted5, "sshpass -p [REDACTED:PASSWORD] ssh dev@server\n");
    }

    #[test]
    fn test_redact_env_secret_assignments() {
        let input1 = "export STRIPE_SECRET_KEY=\"sk_test_1234567890abcdef\"\n";
        let redacted1 = SecretRedactor::redact_str(input1);
        assert_eq!(redacted1, "export STRIPE_SECRET_KEY=[REDACTED:SECRET]\n");

        let input2 = "ADMIN_PASSWORD=ComplexPassword123!\n";
        let redacted2 = SecretRedactor::redact_str(input2);
        assert_eq!(redacted2, "ADMIN_PASSWORD=[REDACTED:SECRET]\n");
    }

    #[test]
    fn test_benign_commands_not_falsely_redacted() {
        // Bare flags without inline password should remain untouched
        let input1 = "mysql -u root -p\n";
        assert_eq!(SecretRedactor::redact_str(input1), input1);

        let input2 = "git commit -m 'update password policy'\n";
        assert_eq!(SecretRedactor::redact_str(input2), input2);

        let input3 = "export TOKEN_COUNT=42\n";
        assert_eq!(SecretRedactor::redact_str(input3), input3);
    }
}
