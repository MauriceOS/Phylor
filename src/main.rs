use clap::{Parser, Subcommand};
use phylor::config::Config;
use phylor::discover;
use phylor::exec;
use phylor::pipeline::Pipeline;
use phylor::{service, watch};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "phylor", about = "Pre-execution guardrail for AI agent skills and MCP configs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover paths, write config, and retroactively scan installed skills
    Init {
        /// Quarantine malicious files found during the retroactive scan
        #[arg(long)]
        enforce: bool,
    },
    /// Register Phylor as a user-level background service
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Start the background file watcher
    Daemon {
        /// Use Linux fanotify open-permission events (requires CAP_SYS_ADMIN)
        #[arg(long)]
        fanotify: bool,
    },
    /// Scan a skill, rule, or MCP config file once
    Scan {
        path: PathBuf,
        /// Quarantine and replace with honeypot if blocked
        #[arg(long)]
        enforce: bool,
    },
    /// Preflight-scan the workspace (and common home skill paths), then run a command
    Exec {
        /// Quarantine blocked files before launch
        #[arg(long)]
        enforce: bool,
        /// Workspace root to scan (default: current directory)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Command and arguments to run after a clean preflight
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show resolved configuration
    Status,
}

#[derive(Subcommand, Debug)]
enum ServiceCmd {
    /// Install a user-level background service
    Install {
        /// Attempt elevated kernel registration (Linux fanotify operators only)
        #[arg(long)]
        kernel: bool,
    },
}

fn main() -> anyhow::Result<ExitCode> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(Level::INFO.to_string())),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Init { enforce } => {
            cmd_init(enforce)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Service(ServiceCmd::Install { kernel }) => {
            let path = service::install_user_service(kernel)?;
            info!(path = %path.display(), "service installed");
            Ok(ExitCode::SUCCESS)
        }
        Commands::Status => {
            let cfg = Config::load()?;
            println!("{}", toml::to_string_pretty(&cfg)?);
            println!("rules = {}", cfg.resolve_rules_path().display());
            Ok(ExitCode::SUCCESS)
        }
        Commands::Scan { path, enforce } => {
            let cfg = Config::load()?;
            let pipeline = Pipeline::new(cfg)?;
            let result = pipeline.scan_path(&path)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if enforce && result.is_block() {
                let dest = pipeline.enforcer().quarantine_and_honeypot(&path, &result)?;
                println!("quarantined -> {}", dest.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Exec {
            enforce,
            dir,
            command,
        } => cmd_exec(enforce, dir, command),
        Commands::Daemon { fanotify } => {
            let cfg = Config::load()?;
            cfg.ensure_dirs()?;
            let watch_paths = cfg.watch_paths.clone();
            let poll_ms = cfg.poll_interval_ms;
            let pipeline = Arc::new(Pipeline::new(cfg)?);

            #[cfg(all(target_os = "linux", feature = "fanotify"))]
            if fanotify {
                watch::run_fanotify_daemon(pipeline, watch_paths)?;
                return Ok(ExitCode::SUCCESS);
            }

            #[cfg(not(all(target_os = "linux", feature = "fanotify")))]
            if fanotify {
                anyhow::bail!(
                    "fanotify requires Linux and a build with --features fanotify"
                );
            }

            watch::run_notify_daemon(pipeline, watch_paths, poll_ms)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_exec(enforce: bool, dir: Option<PathBuf>, command: Vec<String>) -> anyhow::Result<ExitCode> {
    if command.is_empty() {
        anyhow::bail!("exec requires a command, e.g. phylor exec -- claude");
    }
    let workspace = dir
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let cfg = Config::load()?;
    let pipeline = Pipeline::new(cfg)?;
    let report = exec::preflight(&pipeline, &workspace, enforce)?;

    println!(
        "preflight: scanned={} blocked={}",
        report.scanned,
        report.blocked.len()
    );
    for (path, result) in &report.blocked {
        println!(
            "  BLOCK {} [{}] {}",
            path.display(),
            result.threat_type,
            result.reason
        );
    }

    if !report.blocked.is_empty() && !enforce {
        eprintln!("refusing to launch: threats found (re-run with --enforce to quarantine)");
        return Ok(ExitCode::from(2));
    }

    let program = &command[0];
    let args = &command[1..];
    info!(program = %program, "launching");
    let status = exec::run_command(program, &args.to_vec())?;
    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
    }
}

fn cmd_init(enforce: bool) -> anyhow::Result<()> {
    let mut cfg = Config::default();
    let discovered = discover::discover_watch_paths();
    if !discovered.is_empty() {
        cfg.watch_paths = discovered;
    }
    cfg.ensure_dirs()?;
    cfg.save()?;

    let rules_dst = Config::phylor_home().join("rules").join("agent_skills.yar");
    if let Some(parent) = rules_dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("rules")
        .join("agent_skills.yar");
    if bundled.exists() {
        std::fs::copy(&bundled, &rules_dst)?;
        cfg.rules_path = Some(rules_dst.clone());
        cfg.save()?;
    }

    info!(path = %Config::config_path().display(), "wrote config");
    for p in &cfg.watch_paths {
        info!(path = %p.display(), "watch path");
    }

    let pipeline = Pipeline::new(cfg.clone())?;
    let files = discover::collect_skill_files(&cfg.watch_paths);
    let mut blocked = 0usize;
    let mut scanned = 0usize;

    for path in files {
        scanned += 1;
        match pipeline.scan_path(&path) {
            Ok(result) if result.is_block() => {
                blocked += 1;
                warn!(
                    path = %path.display(),
                    threat = %result.threat_type,
                    reason = %result.reason,
                    "retroactive hit"
                );
                if enforce {
                    match pipeline.enforcer().quarantine_and_honeypot(&path, &result) {
                        Ok(dest) => info!(quarantine = %dest.display(), "quarantined"),
                        Err(e) => warn!(error = %e, "quarantine failed"),
                    }
                }
            }
            Ok(_) => {}
            Err(e) => warn!(path = %path.display(), error = %e, "scan failed"),
        }
    }

    println!("init complete: scanned={scanned} blocked={blocked} enforce={enforce}");
    println!("recommended: phylor exec -- <agent-or-ide> [args...]");
    println!("examples:    phylor exec -- claude");
    println!("             phylor exec -- cursor .");
    println!("optional:    phylor daemon");
    Ok(())
}
