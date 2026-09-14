use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Safe,
    Suspicious,
    Malicious,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verdict::Safe => write!(f, "SAFE"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub reason: String,
    pub threat_type: String,
    pub used_llm: bool,
}

impl ScanResult {
    pub fn safe() -> Self {
        Self {
            verdict: Verdict::Safe,
            findings: Vec::new(),
            reason: "no malicious patterns".into(),
            threat_type: String::new(),
            used_llm: false,
        }
    }

    pub fn blocked(
        verdict: Verdict,
        threat_type: impl Into<String>,
        reason: impl Into<String>,
        findings: Vec<Finding>,
        used_llm: bool,
    ) -> Self {
        Self {
            verdict,
            findings,
            reason: reason.into(),
            threat_type: threat_type.into(),
            used_llm,
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self.verdict, Verdict::Malicious | Verdict::Suspicious)
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("yara: {0}")]
    Yara(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("llm: {0}")]
    Llm(String),
}
