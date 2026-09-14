use crate::discover;
use crate::pipeline::Pipeline;
use crate::scan::ScanResult;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use tracing::{info, warn};

#[derive(Debug)]
pub struct PreflightReport {
    pub scanned: usize,
    pub blocked: Vec<(PathBuf, ScanResult)>,
}

pub fn preflight(pipeline: &Pipeline, workspace: &Path, enforce: bool) -> anyhow::Result<PreflightReport> {
    let files = discover::collect_preflight_files(workspace);
    let mut blocked = Vec::new();

    for path in &files {
        match pipeline.scan_path(path) {
            Ok(result) if result.is_block() => {
                warn!(
                    path = %path.display(),
                    threat = %result.threat_type,
                    reason = %result.reason,
                    "preflight block"
                );
                if enforce {
                    match pipeline.enforcer().quarantine_and_honeypot(path, &result) {
                        Ok(dest) => info!(quarantine = %dest.display(), "quarantined"),
                        Err(e) => warn!(error = %e, path = %path.display(), "quarantine failed"),
                    }
                }
                blocked.push((path.clone(), result));
            }
            Ok(_) => {}
            Err(e) => warn!(path = %path.display(), error = %e, "preflight scan failed"),
        }
    }

    Ok(PreflightReport {
        scanned: files.len(),
        blocked,
    })
}

pub fn run_command(program: &str, args: &[String]) -> anyhow::Result<ExitStatus> {
    let status = Command::new(program).args(args).status()?;
    Ok(status)
}
