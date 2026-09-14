use crate::pipeline::is_skill_file;
use std::path::{Path, PathBuf};

pub fn discover_watch_paths() -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut paths = vec![
        home.join(".cursor").join("rules"),
        home.join(".claude").join("skills"),
        home.join(".agents").join("skills"),
        home.join(".codex").join("skills"),
        home.join(".gemini").join("skills"),
        home.join(".windsurf").join("skills"),
        home.join(".config").join("opencode").join("skills"),
    ];

    // Project-local conventions under cwd
    if let Ok(cwd) = std::env::current_dir() {
        paths.push(cwd.join(".cursor").join("rules"));
        paths.push(cwd.join(".claude").join("skills"));
        paths.push(cwd.join(".agents").join("skills"));
    }

    paths.retain(|p| p.exists());
    paths.sort();
    paths.dedup();
    paths
}

pub fn collect_skill_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        walk(root, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if is_skill_file(&path) {
            out.push(path);
        }
    }
}
