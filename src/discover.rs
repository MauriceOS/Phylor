use crate::pipeline::is_watched_file;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".turbo",
    "vendor",
    ".idea",
    ".vscode",
    "coverage",
    ".phylor",
];

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

/// Known agent roots plus a deep workspace walk for misplaced skill files.
pub fn discover_preflight_roots(workspace: &Path) -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let mut roots = agent_workspace_roots(workspace);
    roots.extend(agent_home_roots(&home));
    roots.push(workspace.to_path_buf());
    roots.retain(|p| p.exists());
    roots.sort();
    roots.dedup();
    roots
}

/// Collect watched files from known roots and by scanning the workspace tree.
pub fn collect_preflight_files(workspace: &Path) -> Vec<PathBuf> {
    let mut files = collect_skill_files(&discover_preflight_roots(workspace));
    files.extend(scan_tree(workspace, 14));
    files.sort();
    files.dedup();
    files
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
        workspace.join("skills"),
        workspace.join(".skills"),
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
        out.extend(scan_tree(root, 8));
    }
    out.sort();
    out.dedup();
    out
}

/// Deep walk used for auto-discovery of skills outside conventional folders.
pub fn scan_tree(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out, 0, max_depth);
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize, max_depth: usize) {
    if depth > max_depth {
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
            if SKIP_DIRS.iter().any(|s| *s == name) {
                continue;
            }
            walk(&path, out, depth + 1, max_depth);
        } else if is_watched_file(&path) {
            out.push(path);
        }
    }
}
