use crate::scan::types::ScanResult;
use std::path::Path;
use tracing::{debug, warn};

pub fn alert_block(path: &Path, result: &ScanResult) {
    let threat = if result.threat_type.is_empty() {
        result.verdict.to_string()
    } else {
        result.threat_type.clone()
    };
    let body = format!(
        "Blocked {} in {}\n{}",
        threat,
        path.display(),
        truncate(&result.reason, 180)
    );

    match notify_rust::Notification::new()
        .summary("Phylor Security Alert")
        .body(&body)
        .appname("Phylor")
        .timeout(notify_rust::Timeout::Milliseconds(15_000))
        .show()
    {
        Ok(_) => debug!(path = %path.display(), "desktop notification sent"),
        Err(e) => warn!(error = %e, "desktop notification failed"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let clipped: String = s.chars().take(max).collect();
    format!("{clipped}…")
}
