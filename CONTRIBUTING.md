# Contributing to Phylor

Phylor is at v0.2. Prefer small, reviewable changes.

## Before you start

1. Open an issue for substantial features or architectural changes.
2. Keep PRs scoped to one concern when possible.
3. Do not commit secrets, live malware outside `fixtures/`, or personal skill trees.

## Setup

```bash
git clone https://github.com/MauriceOS/Phylor.git
cd Phylor
cargo test
```

## Priority areas

- MCP and remote-hydration detections with low false-positive rates
- `phylor exec` UX and CI packaging
- False-positive reports: OS, agent, redacted snippet, Phylor verdict
- Fixture coverage under `fixtures/` and `tests/`

Pull requests to `main` run `.github/workflows/rust.yml` (`cargo build --locked` and `cargo test --locked` on Linux, Windows, and macOS).

When changing detection logic, update both:

- `rules/agent_skills.yar`
- `src/scan/yara.rs`

Default contributions should target `exec`, `scan`, and the user-level watcher. Extend the Linux `fanotify` path only when that is the explicit goal of the change.

## Code style

- Clear Rust over clever Rust
- Comments only where intent is not obvious from the code
- Follow existing module boundaries (`pipeline`, `exec`, `watch`, `scan`, `enforce`)

## Pull requests

- State the threat or bug addressed
- Include `cargo test` results
- Note platforms you could not verify

## Conduct

Be respectful. Security research discussion is welcome.
