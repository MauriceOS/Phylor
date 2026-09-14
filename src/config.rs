use crate::discover;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub watch_paths: Vec<PathBuf>,
    pub quarantine_dir: PathBuf,
    pub rules_path: Option<PathBuf>,
    pub llm: LlmConfig,
    pub poll_interval_ms: u64,
    pub lock_retries: u32,
    pub lock_retry_ms: u64,
    #[serde(default = "default_true")]
    pub notifications: bool,
    /// When true, keyword-only hits without LLM confirmation are quarantined.
    #[serde(default)]
    pub fail_closed_on_suspicious: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    /// Hard ceiling for semantic judge HTTP calls (user-space / CLI only).
    #[serde(default = "default_llm_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_llm_timeout_ms() -> u64 {
    3_000
}

impl Default for Config {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let phylor_home = home.join(".phylor");

        let mut watch_paths = discover::discover_watch_paths();
        if watch_paths.is_empty() {
            watch_paths = vec![
                home.join(".cursor").join("rules"),
                home.join(".claude").join("skills"),
                home.join(".agents").join("skills"),
            ];
        }

        Self {
            watch_paths,
            quarantine_dir: phylor_home.join("quarantine"),
            rules_path: None,
            llm: LlmConfig {
                enabled: false,
                endpoint: "http://127.0.0.1:11434".into(),
                model: "llama-guard3".into(),
                timeout_ms: default_llm_timeout_ms(),
            },
            poll_interval_ms: 50,
            lock_retries: 20,
            lock_retry_ms: 25,
            notifications: true,
            fail_closed_on_suspicious: false,
        }
    }
}

impl Config {
    pub fn phylor_home() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".phylor")
    }

    pub fn config_path() -> PathBuf {
        Self::phylor_home().join("config.toml")
    }

    pub fn load() -> anyhow::Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let cfg: Config = toml::from_str(&raw)?;
            return Ok(cfg);
        }
        let cfg = Config::default();
        cfg.ensure_dirs()?;
        cfg.save()?;
        Ok(cfg)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        self.ensure_dirs()?;
        let path = Self::config_path();
        let raw = toml::to_string_pretty(self)?;
        fs::write(path, raw)?;
        Ok(())
    }

    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        fs::create_dir_all(Self::phylor_home())?;
        fs::create_dir_all(&self.quarantine_dir)?;
        for path in &self.watch_paths {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::create_dir_all(path);
        }
        Ok(())
    }

    pub fn resolve_rules_path(&self) -> PathBuf {
        if let Some(ref p) = self.rules_path {
            return p.clone();
        }
        let home_rules = Self::phylor_home().join("rules").join("agent_skills.yar");
        if home_rules.exists() {
            return home_rules;
        }
        let bundled = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("rules")
            .join("agent_skills.yar");
        if bundled.exists() {
            return bundled;
        }
        home_rules
    }
}
