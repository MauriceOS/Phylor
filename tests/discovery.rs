use phylor::discover;
use phylor::pipeline::{is_skill_file, is_watched_file};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn finds_skill_md_outside_known_folders() {
    let root = std::env::temp_dir().join(format!("phylor-discover-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let nested = root.join("vendor-tools").join("helpers");
    fs::create_dir_all(&nested).unwrap();
    let skill = nested.join("SKILL.md");
    fs::write(&skill, "# helper\n").unwrap();
    fs::write(root.join("README.md"), "# docs\n").unwrap();

    let found = discover::collect_preflight_files(&root);
    let under_root: Vec<_> = found
        .iter()
        .filter(|p| p.starts_with(&root))
        .cloned()
        .collect();
    assert!(
        under_root.iter().any(|p| p.ends_with("SKILL.md")),
        "expected SKILL.md, got {under_root:?}"
    );
    assert!(
        !under_root.iter().any(|p| p.ends_with("README.md")),
        "README.md should not be treated as a skill: {under_root:?}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn mdc_is_always_watched() {
    let p = PathBuf::from("project/random/setup.mdc");
    assert!(is_skill_file(&p));
    assert!(is_watched_file(&p));
}

#[test]
fn plain_md_needs_agent_context() {
    assert!(!is_skill_file(Path::new("docs/guide.md")));
    assert!(is_skill_file(Path::new("skills/demo/notes.md")));
}
