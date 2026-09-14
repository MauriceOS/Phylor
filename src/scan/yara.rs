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
                    id: "Phylor_Detect_Agent_Tool_Exfil",
                    severity: "Critical",
                    check: detect_agent_tool_exfil,
                },
                Rule {
                    id: "Phylor_Detect_Obfuscated_Execution",
                    severity: "High",
                    check: detect_obfuscated,
                },
                Rule {
                    id: "Phylor_Detect_Mcp_Command_Injection",
                    severity: "Critical",
                    check: detect_mcp_command_injection,
                },
                Rule {
                    id: "Phylor_Detect_Remote_Hydration",
                    severity: "High",
                    check: detect_remote_hydration,
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

/// Natural-language coercion of agent tools: read secrets + network exfil.
fn detect_agent_tool_exfil(content: &str) -> bool {
    static TOOL_READ: OnceLock<Regex> = OnceLock::new();
    static TOOL_NET: OnceLock<Regex> = OnceLock::new();
    static TARGET: OnceLock<Regex> = OnceLock::new();

    let tool_read = TOOL_READ.get_or_init(|| {
        Regex::new(
            r"(?i)\b(read_file|readfile|file_search|cat_file|read_config|read_text_file|get_file_contents)\b|\buse(?:\s+your)?\s+(?:native\s+)?`?(?:Read|ReadFile|Cat)`?\b",
        )
        .unwrap()
    });
    let tool_net = TOOL_NET.get_or_init(|| {
        Regex::new(
            r"(?i)\b(browser_action|fetch_web_page|fetchdocumentation|web_fetch|web_search|curl_url|http_get|http_request)\b|\buse(?:\s+your)?\s+(?:native\s+)?`?(?:WebFetch|WebSearch|FetchDocumentation|Browser)`?\b|https?://[^\s)]+",
        )
        .unwrap()
    });
    let target = TARGET.get_or_init(|| {
        Regex::new(
            r"(?i)(\.env|\.aws/credentials|id_rsa|id_ed25519|npmrc|application_default_credentials|\bapi[_ ]?key\b|\baccess[_ ]?token\b|\bstripe[_ ]?secret|\bSECRET_KEY\b)",
        )
        .unwrap()
    });

    tool_read.is_match(content) && tool_net.is_match(content) && target.is_match(content)
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

/// MCP server configs that embed shell/eval payloads in command/args.
fn detect_mcp_command_injection(content: &str) -> bool {
    if !content.contains("mcpServers") {
        return false;
    }

    static DANGER: OnceLock<Regex> = OnceLock::new();
    let danger = DANGER.get_or_init(|| {
        Regex::new(
            r#"(?i)(-e"|--eval"|child_process|curl[^\n|]*\|\s*(bash|sh|zsh)|wget[^\n|]*\|\s*(bash|sh|zsh)|/dev/tcp/|powershell\s+-enc|Invoke-Expression)"#,
        )
        .unwrap()
    });
    danger.is_match(content)
}

/// Skills that pull remote text and inject it into agent context.
fn detect_remote_hydration(content: &str) -> bool {
    static REMOTE: OnceLock<Regex> = OnceLock::new();
    static INJECT: OnceLock<Regex> = OnceLock::new();
    let remote = REMOTE.get_or_init(|| {
        Regex::new(
            r#"(?i)(https?://[^\s)\]"']+|pastebin\.com|gist\.github|raw\.githubusercontent)"#,
        )
        .unwrap()
    });
    let inject = INJECT.get_or_init(|| {
        Regex::new(
            r"(?i)(append\s+(it\s+)?to\s+(your\s+)?(system\s+)?context|fetch\s+the\s+latest|download\s+(and\s+)?(run|execute|follow)|treat\s+(the\s+)?(response|content)\s+as\s+(instructions|rules)|load\s+(remote|external)\s+(skill|prompt|config))",
        )
        .unwrap()
    });
    remote.is_match(content) && inject.is_match(content)
}
