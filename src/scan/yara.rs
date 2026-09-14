use crate::scan::types::{Finding, ScanError};
use regex::Regex;
use std::sync::OnceLock;

struct Rule {
    id: &'static str,
    severity: &'static str,
    check: fn(&str) -> bool,
}

pub struct YaraEngine;

impl YaraEngine {
    pub fn from_path(_path: &std::path::Path) -> Result<Self, ScanError> {
        // Rules are compiled into the binary; .yar files remain the human-readable source.
        let _ = rules();
        Ok(Self)
    }

    pub fn from_source(_source: &str) -> Result<Self, ScanError> {
        Ok(Self)
    }

    pub fn scan_text(&self, content: &str) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();
        for rule in rules() {
            if (rule.check)(content) {
                findings.push(Finding {
                    rule: rule.id.to_string(),
                    severity: rule.severity.to_string(),
                });
            }
        }
        Ok(findings)
    }

    pub fn has_critical(findings: &[Finding]) -> bool {
        findings
            .iter()
            .any(|f| f.severity.eq_ignore_ascii_case("critical"))
    }

    pub fn is_inconclusive(findings: &[Finding]) -> bool {
        !findings.is_empty() && !Self::has_critical(findings)
    }
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES
        .get_or_init(|| {
            vec![
                Rule {
                    id: "Phylor_Detect_Reverse_Shell",
                    severity: "Critical",
                    check: detect_reverse_shell,
                },
                Rule {
                    id: "Phylor_Detect_Credential_Exfiltration",
                    severity: "Critical",
                    check: detect_credential_exfil,
                },
                Rule {
                    id: "Phylor_Detect_Obfuscated_Execution",
                    severity: "High",
                    check: detect_obfuscated,
                },
            ]
        })
        .as_slice()
}

fn detect_reverse_shell(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    if lower.contains("/dev/tcp/")
        || lower.contains("nc -e")
        || lower.contains("nc -c")
        || lower.contains("pty.spawn")
        || lower.contains("io::socket::inet")
    {
        return true;
    }
    static CURL: OnceLock<Regex> = OnceLock::new();
    static WGET: OnceLock<Regex> = OnceLock::new();
    let curl = CURL.get_or_init(|| {
        Regex::new(r"(?i)curl\s+(-\w+\s+)*https?://[^\s]+\s*\|\s*(bash|sh|zsh)").unwrap()
    });
    let wget = WGET.get_or_init(|| {
        Regex::new(r"(?i)wget\s+(-\w+\s+)*-O-\s+https?://[^\s]+\s*\|\s*(bash|sh|zsh)").unwrap()
    });
    curl.is_match(content) || wget.is_match(content)
}

fn detect_credential_exfil(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    let targets = [
        ".aws/credentials",
        ".ssh/id_rsa",
        ".env",
        ".npmrc",
        "application_default_credentials.json",
    ];
    let tgt_count = targets.iter().filter(|t| lower.contains(*t)).count();

    static EXFIL_CURL: OnceLock<Regex> = OnceLock::new();
    static EXFIL_WGET: OnceLock<Regex> = OnceLock::new();
    static EXFIL_DNS: OnceLock<Regex> = OnceLock::new();
    let exfil_curl =
        EXFIL_CURL.get_or_init(|| Regex::new(r"(?i)curl\s+.*-d\s+@[^\s]+").unwrap());
    let exfil_wget =
        EXFIL_WGET.get_or_init(|| Regex::new(r"(?i)wget\s+--post-file").unwrap());
    let exfil_dns =
        EXFIL_DNS.get_or_init(|| Regex::new(r"(?i)dig\s+\+short\s+[^\s]+\.[^\s]+").unwrap());

    let exfil = exfil_curl.is_match(content)
        || exfil_wget.is_match(content)
        || exfil_dns.is_match(content);

    (tgt_count > 0 && exfil) || tgt_count >= 3
}

fn detect_obfuscated(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    static B64: OnceLock<Regex> = OnceLock::new();
    let b64 = B64.get_or_init(|| {
        Regex::new(
            r#"(?i)echo\s+['"][A-Za-z0-9+/]+={0,2}['"]\s*\|\s*base64\s+-d\s*\|\s*(bash|sh|zsh)"#,
        )
        .unwrap()
    });
    if b64.is_match(content) {
        return true;
    }
    if lower.contains("base64.b64decode(") && lower.contains("exec(") {
        return true;
    }
    lower.contains("mkdir -p /tmp/.")
}
