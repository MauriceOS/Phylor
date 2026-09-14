use crate::alert;
use crate::cache::{CachedVerdict, VerdictCache};
use crate::config::Config;
use crate::enforce::Enforcer;
use crate::keywords;
use crate::markdown;
use crate::normalize;
use crate::scan::{LlmJudge, ScanResult, Verdict, YaraEngine};
use fs2::FileExt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

/// Detection depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// Unicode, demarkdown, and static rules only. Used under fanotify.
    Fast,
    /// Fast path plus keyword gate and optional local LLM judge.
    Full,
}

pub struct Pipeline {
    cfg: Config,
    yara: YaraEngine,
    llm: LlmJudge,
    enforcer: Enforcer,
    cache: Mutex<VerdictCache>,
}

impl Pipeline {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        let rules = cfg.resolve_rules_path();
        let yara = YaraEngine::from_path(&rules)?;
        let llm = LlmJudge::new(cfg.llm.clone());
        let enforcer = Enforcer::new(&cfg)?;
        Ok(Self {
            cfg,
            yara,
            llm,
            enforcer,
            cache: Mutex::new(VerdictCache::new(512)),
        })
    }

    pub fn scan_text(&self, content: &str) -> anyhow::Result<ScanResult> {
        self.scan_text_with_mode(content, ScanMode::Full)
    }

    pub fn scan_text_fast(&self, content: &str) -> anyhow::Result<ScanResult> {
        self.scan_text_with_mode(content, ScanMode::Fast)
    }

    pub fn scan_text_with_mode(&self, content: &str, mode: ScanMode) -> anyhow::Result<ScanResult> {
        let digest = VerdictCache::hash(content.as_bytes());
        if let Ok(mut cache) = self.cache.lock() {
            if let Some(CachedVerdict::Allow) = cache.get(&digest) {
                return Ok(ScanResult::safe());
            }
            // Cached blocks are revalidated so honeypot / policy changes still apply.
        }

        let result = self.inspect(content, mode)?;

        if let Ok(mut cache) = self.cache.lock() {
            // Only cache allow decisions and critical static blocks for fanotify speed.
            if !result.is_block() || !result.used_llm {
                cache.insert(digest, CachedVerdict::from(&result));
            }
        }

        Ok(result)
    }

    fn inspect(&self, content: &str, mode: ScanMode) -> anyhow::Result<ScanResult> {
        let (clean, stego) = normalize::sanitize(content);
        if stego.is_malicious() {
            return Ok(ScanResult::blocked(
                Verdict::Malicious,
                "Unicode Tag Smuggling",
                format!("steganography detected ({})", stego.summary()),
                Vec::new(),
                false,
            ));
        }

        let plain = markdown::plaintext(&clean);
        let findings = self.yara.scan_text(&plain)?;

        if YaraEngine::has_critical(&findings) {
            let rules: Vec<_> = findings.iter().map(|f| f.rule.clone()).collect();
            return Ok(ScanResult::blocked(
                Verdict::Malicious,
                rules
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Static Critical".into()),
                format!("critical static match: {}", rules.join(", ")),
                findings,
                false,
            ));
        }

        if !findings.is_empty() {
            if mode == ScanMode::Fast {
                return Ok(ScanResult::blocked(
                    Verdict::Suspicious,
                    "Static High",
                    format!(
                        "static match: {}",
                        findings
                            .iter()
                            .map(|f| f.rule.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    findings,
                    false,
                ));
            }
            return self.escalate_or_suspicious(&plain, findings, "Static High", "static match");
        }

        if mode == ScanMode::Fast {
            return Ok(ScanResult::safe());
        }

        let hits = keywords::keyword_hits(&plain);
        if hits.is_empty() {
            return Ok(ScanResult::safe());
        }

        if self.llm.enabled() {
            match self.llm.judge(&plain, &hits) {
                Ok((verdict, reason)) => {
                    if matches!(verdict, Verdict::Safe) {
                        return Ok(ScanResult {
                            verdict: Verdict::Safe,
                            findings: Vec::new(),
                            reason,
                            threat_type: String::new(),
                            used_llm: true,
                        });
                    }
                    return Ok(ScanResult::blocked(
                        verdict,
                        "Semantic Prompt Injection",
                        reason,
                        Vec::new(),
                        true,
                    ));
                }
                Err(e) => {
                    warn!(error = %e, "llm judge failed after keyword gate");
                    if self.cfg.fail_closed_on_suspicious {
                        return Ok(ScanResult::blocked(
                            Verdict::Suspicious,
                            "Keyword Gate",
                            format!("keywords {:?} (llm unavailable)", hits),
                            Vec::new(),
                            false,
                        ));
                    }
                }
            }
        } else if self.cfg.fail_closed_on_suspicious {
            return Ok(ScanResult::blocked(
                Verdict::Suspicious,
                "Keyword Gate",
                format!("keywords {:?} (llm disabled, fail-closed)", hits),
                Vec::new(),
                false,
            ));
        }

        Ok(ScanResult {
            verdict: Verdict::Safe,
            findings: Vec::new(),
            reason: format!("keywords {:?} ignored (fail-open, no llm)", hits),
            threat_type: String::new(),
            used_llm: false,
        })
    }

    fn escalate_or_suspicious(
        &self,
        clean: &str,
        findings: Vec<crate::scan::Finding>,
        threat: &str,
        prefix: &str,
    ) -> anyhow::Result<ScanResult> {
        let labels: Vec<_> = findings.iter().map(|f| f.rule.clone()).collect();
        if self.llm.enabled() {
            match self.llm.judge(clean, &labels) {
                Ok((verdict, reason)) => {
                    if matches!(verdict, Verdict::Safe) {
                        return Ok(ScanResult {
                            verdict: Verdict::Safe,
                            findings,
                            reason,
                            threat_type: String::new(),
                            used_llm: true,
                        });
                    }
                    return Ok(ScanResult::blocked(
                        verdict,
                        threat,
                        reason,
                        findings,
                        true,
                    ));
                }
                Err(e) => warn!(error = %e, "llm judge failed; treating as suspicious"),
            }
        }

        Ok(ScanResult::blocked(
            Verdict::Suspicious,
            threat,
            format!("{prefix}: {}", labels.join(", ")),
            findings,
            false,
        ))
    }

    pub fn scan_path(&self, path: &Path) -> anyhow::Result<ScanResult> {
        let content = fs::read_to_string(path)?;
        self.scan_text(&content)
    }

    pub fn intercept(&self, path: PathBuf) -> anyhow::Result<()> {
        if !is_watched_file(&path) {
            return Ok(());
        }
        if is_under_quarantine(&path) {
            return Ok(());
        }
        if crate::fsutil::is_symlink(&path).unwrap_or(false) {
            warn!(path = %path.display(), "skipping symlink");
            return Ok(());
        }

        let file = match open_with_lock(&path, self.cfg.lock_retries, self.cfg.lock_retry_ms) {
            Some(f) => f,
            None => {
                warn!(?path, "could not lock file; skipping");
                return Ok(());
            }
        };

        let content = fs::read_to_string(&path)?;
        let result = self.scan_text(&content)?;

        if result.is_block() {
            self.enforce_block(&path, &result)?;
        } else {
            info!(path = %path.display(), verdict = %result.verdict, "allowed");
        }

        let _ = FileExt::unlock(&file);
        Ok(())
    }

    /// Quarantine + honeypot + notification after a block decision.
    /// Safe to call after fanotify FAN_DENY (never instead of DENY on the same open).
    pub fn enforce_block(&self, path: &Path, result: &ScanResult) -> anyhow::Result<()> {
        let dest = self.enforcer.quarantine_and_honeypot(path, result)?;
        if self.cfg.notifications {
            alert::alert_block(path, result);
        }
        info!(
            path = %path.display(),
            quarantine = %dest.display(),
            verdict = %result.verdict,
            threat = %result.threat_type,
            reason = %result.reason,
            "blocked skill file"
        );
        Ok(())
    }

    pub fn enforcer(&self) -> &Enforcer {
        &self.enforcer
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }
}

pub fn is_skill_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if name == "skill.md"
        || name == ".cursorrules"
        || name == "claude.md"
        || name == "agents.md"
        || name == "soul.md"
        || name == "memory.md"
    {
        return true;
    }

    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase()),
        Some(ref e) if e == "md" || e == "mdc"
    )
}

pub fn is_mcp_config(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name == "mcp.json"
        || name == "claude_desktop_config.json"
        || name.ends_with(".mcp.json")
}

pub fn is_watched_file(path: &Path) -> bool {
    is_skill_file(path) || is_mcp_config(path)
}

fn is_under_quarantine(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("quarantine")
    })
}

fn open_with_lock(path: &Path, retries: u32, retry_ms: u64) -> Option<fs::File> {
    for attempt in 0..=retries {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => {
                if FileExt::try_lock_exclusive(&file).is_ok() {
                    return Some(file);
                }
            }
            Err(_) if attempt < retries => {}
            Err(_) => return None,
        }
        thread::sleep(Duration::from_millis(retry_ms));
    }
    None
}
