# Contributing to Phylor

Thanks for helping harden AI agent skill loading. This project is early (v0.1). Small, focused changes are easier to review than large rewrites.

## Before you start

1. Open an issue for substantial features or architectural changes.
2. Keep PRs scoped: one concern per PR when possible.
3. Do not commit secrets, live malware samples outside `fixtures/`, or personal skill trees from your machine.

## Setup

```bash
git clone https://github.com/<owner>/Phylor.git
cd Phylor
cargo test
```

## What we need most

- Additional static detections with low false-positive rates
- Platform service install fixes (systemd, LaunchAgent, Windows Task Scheduler)
- Clear false-positive reports: OS, agent, redacted skill snippet, Phylor verdict
- Tests for new rules under `fixtures/` and `tests/`

When you change detection logic, update both:

- `rules/agent_skills.yar` (documentation / portable rule text)
- `src/scan/yara.rs` (what the daemon actually runs today)

## Code style

- Prefer clear Rust over clever Rust.
- Avoid noisy comments that restate the code.
- Match existing module boundaries (`pipeline`, `watch`, `scan`, `enforce`).

## Pull requests

- Describe the threat or bug you are addressing.
- Include `cargo test` results.
- Note any platform you could not verify.

## Conduct

Be respectful. Security research discussion is welcome; harassment and drive-by insult PRs are not.
