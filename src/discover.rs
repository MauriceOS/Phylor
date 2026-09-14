use crate::pipeline::is_watched_file;
use std::path::{Path, PathBuf};

pub fn discover_watch_paths() -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut paths = agent_home_roots(&home);

    if let Ok(cwd) = std::env::current_dir() {
        paths.extend(agent_workspace_roots(&cwd));
        paths.push(cwd);
    }

    paths.retain(|p| p.exists());
    paths.sort();
    paths.dedup();
    paths
}

/// Paths to preflight before launching an agent or IDE (`phylor exec`).
pub fn discover_preflight_roots(workspace: &Path) -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut roots = agent_workspace_roots(workspace);
    roots.extend(agent_home_roots(&home));
    roots.retain(|p| p.exists());
    roots.sort();
    roots.dedup();
    roots
}

fn agent_home_roots(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".cursor").join("rules"),
        home.join(".cursor"),
        home.join(".claude").join("skills"),
        home.join(".claude"),
        home.join(".agents").join("skills"),
        home.join(".codex").join("skills"),
        home.join(".gemini").join("skills"),
        home.join(".windsurf").join("skills"),
        home.join(".config").join("opencode").join("skills"),
        home.join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude_desktop_config.json"),
        home.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json"),
        home.join(".config")
            .join("Claude")
            .join("claude_desktop_config.json"),
    ]
}

fn agent_workspace_roots(workspace: &Path) -> Vec<PathBuf> {
    vec![
        workspace.join(".cursor"),
        workspace.join(".claude"),
        workspace.join(".agents"),
        workspace.join(".codex"),
        workspace.join(".gemini"),
        workspace.join(".windsurf"),
        workspace.join(".opencode"),
    ]
}

pub fn collect_skill_files(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        if root.is_file() {
            if is_watched_file(root) {
                out.push(root.clone());
            }
            continue;
        }
        walk(root, &mut out, 0);
    }
    out.sort();
    out.dedup();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if name == "node_modules" || name == ".git" || name == "target" {
                continue;
            }
            walk(&path, out, depth + 1);
        } else if is_watched_file(&path) {
            out.push(path);
        }
    }
}
