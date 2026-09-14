use crate::pipeline::{is_watched_file, Pipeline};
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub fn run_notify_daemon(
    pipeline: Arc<Pipeline>,
    watch_paths: Vec<PathBuf>,
    poll_ms: u64,
) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel();
    let mut watcher = RecommendedWatcher::new(
        tx,
        NotifyConfig::default().with_poll_interval(Duration::from_millis(poll_ms)),
    )?;

    for path in &watch_paths {
        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }
        watcher.watch(path, RecursiveMode::Recursive)?;
        info!(path = %path.display(), "watching");
    }

    info!("phylor notify daemon active");

    for res in rx {
        match res {
            Ok(event) => handle_event(event, &pipeline),
            Err(e) => error!(error = %e, "watch error"),
        }
    }

    Ok(())
}

fn handle_event(event: Event, pipeline: &Pipeline) {
    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {}
        _ => return,
    }

    for path in event.paths {
        if !is_watched_file(&path) || !path.is_file() {
            continue;
        }
        if let Err(e) = pipeline.intercept(path.clone()) {
            warn!(path = %path.display(), error = %e, "intercept failed");
        }
    }
}
