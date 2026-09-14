use crate::alert;
use crate::config::Config;
use crate::enforce::Enforcer;
use crate::keywords;
use crate::normalize;
use crate::scan::{LlmJudge, ScanResult, Verdict, YaraEngine};
use fs2::FileExt;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

pub struct Pipeline {
    cfg: Config,
    yara: YaraEngine,
    llm: LlmJudge,
    enforcer: Enforcer,
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
        })
    }

    pub fn scan_text(&self, content: &str) -> anyhow::Result<ScanResult> {
        // 1. Unicode / stego (Policy A)
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

        // 2. YARA static
        let findings = self.yara.scan_text(&clean)?;

        if YaraEngine::has_critical(&findings) {
            let rules: Vec<_> = findings.iter().map(|f| f.rule.clone()).collect();
            return Ok(ScanResult::blocked(
                Verdict::Malicious,
                rules.first().cloned().unwrap_or_else(|| "YARA Critical".into()),
                format!("critical static match: {}", rules.join(", ")),
                findings,
                false,
            ));
        }

        if !findings.is_empty() {
            return self.escalate_or_suspicious(
                &clean,
                findings,
                "YARA High",
                "static match",
            );
        }

        // 3. Keyword gate → optional LLM (even when YARA clean)
        let hits = keywords::keyword_hits(&clean);
        if hits.is_empty() {
            return Ok(ScanResult::safe());
        }

        if self.llm.enabled() {
            match self.llm.judge(&clean, &hits) {
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

        // Fail-open: keywords alone without LLM confirmation
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
        if !is_skill_file(&path) {
            return Ok(());
        }
        if is_under_quarantine(&path) {
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
            let dest = self.enforcer.quarantine_and_honeypot(&path, &result)?;
            if self.cfg.notifications {
                alert::alert_block(&path, &result);
            }
            info!(
                path = %path.display(),
                quarantine = %dest.display(),
                verdict = %result.verdict,
                threat = %result.threat_type,
                reason = %result.reason,
                "blocked skill file"
            );
        } else {
            info!(path = %path.display(), verdict = %result.verdict, "allowed");
        }

        let _ = FileExt::unlock(&file);
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
