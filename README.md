# Phylor

<p align="center">
  <img src="assets/phylor-banner.png" alt="Phylor" width="420" />
</p>

<p align="center">
  <a href="https://github.com/MauriceOS/Phylor/actions/workflows/rust.yml"><img src="https://github.com/MauriceOS/Phylor/actions/workflows/rust.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.88%2B-orange.svg" alt="Rust 1.88+" /></a>
</p>

Pre-execution guardrail for AI coding agent skills, rules, and MCP configs.

Phylor inspects instruction files (`SKILL.md`, `.mdc` / rule files, MCP JSON, and related paths) for supply-chain payloads before they are loaded by coding agents such as **Cursor**, **Claude Code**, **Gemini CLI**, **Codex**, **Windsurf**, and OpenCode-compatible setups.

**v0.2** — binaries are published on GitHub Releases; you can also build from source.

## How it works

Phylor runs in user space by default:

1. **`phylor exec`** — scan the workspace, then launch your agent or IDE
2. **`phylor scan` / `init`** — one-off and retroactive checks
3. **`phylor daemon`** — optional background watcher (user-level)

A Linux `fanotify` mode is available for operators who need in-kernel open authorization. It requires elevated privileges and is not the default install path. Equivalent kernel hooks on macOS and Windows need platform entitlements or signed drivers that a typical source build cannot provide.

## What it detects

| Layer | Coverage |
| --- | --- |
| Unicode / Policy A | Tags block, bidi spoofing, dense zero-width abuse |
| Markdown plaintext | Emphasis/HTML fragmentation before static matching |
| Static rules | Shell pipes, credential exfil, obfuscation, agent tool coercion |
| MCP configs | Dangerous `command` / `args` patterns (eval, `child_process`, `curl\|bash`) |
| Remote hydration | Fetch remote text and inject it into agent context |
| Optional LLM | Local Ollama judge for ambiguous prompt injection (CLI / notify only) |

Current limits include multi-file split payloads and fully dynamic remote stages. Phylor reduces risk; it does not replace agent permission discipline.

## Requirements

- Rust **1.88+** (stable)
- Optional: [Ollama](https://ollama.com) for semantic judging

## Install

### Prebuilt binaries (Windows, macOS, Linux)

Download the archive for your platform from
[GitHub Releases](https://github.com/MauriceOS/Phylor/releases):

| Platform | Asset |
| --- | --- |
| Windows x64 | `phylor-x86_64-pc-windows-msvc.zip` → `phylor.exe` |
| Linux x64 | `phylor-x86_64-unknown-linux-gnu.tar.gz` → `phylor` |
| macOS Apple Silicon | `phylor-aarch64-apple-darwin.tar.gz` → `phylor` |
| macOS Intel | `phylor-x86_64-apple-darwin.tar.gz` → `phylor` |

Extract, place the binary on your `PATH`, then run `phylor init`.

Releases are built automatically when a version tag is pushed (`v0.2.1`, etc.).

### Build from source

```bash
git clone https://github.com/MauriceOS/Phylor.git
cd Phylor
cargo build --release
```

After building: `target/release/phylor` on macOS/Linux, or `target/release/phylor.exe` on Windows.

### Windows (from source)

```powershell
cargo build --release
.\target\release\phylor.exe init
.\target\release\phylor.exe exec -- cursor .
```

### macOS / Linux (from source)

```bash
cargo build --release
./target/release/phylor init
./target/release/phylor exec -- claude
./target/release/phylor exec -- cursor .
./target/release/phylor exec -- gemini
```

## Supported agent layouts

Phylor checks known agent directories and also **walks the workspace** for high-confidence files even when they sit outside those folders (for example a nested `SKILL.md` under `vendor-tools/...`).

| Agent / tool | Typical paths |
| --- | --- |
| Cursor | `~/.cursor/rules`, project `.cursor/`, `mcp.json` |
| Claude Code | `~/.claude/skills`, project `.claude/`, Claude desktop MCP config |
| Gemini CLI | `~/.gemini/skills` |
| Codex | `~/.codex/skills` |
| Windsurf | `~/.windsurf/skills` |
| OpenCode / agents | `~/.agents/skills`, `~/.config/opencode/skills`, project `.agents/` |

Watched names include `SKILL.md`, `*.mdc`, `mcp.json`, `claude_desktop_config.json`, `.cursorrules`, `CLAUDE.md`, `AGENTS.md`, and Markdown under skill/rules-style directories. Ordinary docs like `README.md` are ignored.

List everything Phylor would scan:

```bash
phylor discover
phylor discover --dir /path/to/project
```
## Quick start

```bash
# Discover paths, write ~/.phylor/config.toml, retroactive scan
phylor init
phylor init --enforce

# See which skill/MCP files Phylor found (including odd paths)
phylor discover

# Preflight then launch (any agent CLI / IDE)
phylor exec -- cursor .
phylor exec -- claude
phylor exec -- gemini
phylor exec --enforce -- cursor .

# One-off scan (skills, rules, or MCP JSON)
phylor scan path/to/SKILL.md
phylor scan .cursor/mcp.json --enforce
phylor scan ~/.claude/skills/some-skill/SKILL.md

# Optional background watcher
phylor daemon
```

Without `--enforce`, `phylor exec` exits with code `2` if threats are found and does not launch the command.

| Exit code | Meaning |
| --- | --- |
| `0` | Safe / clean (or launched command succeeded) |
| `1` | Tool error (missing config, I/O failure, bad arguments) |
| `2` | Threat detected; launch refused |

## Configuration

Default: `~/.phylor/config.toml`

| Key | Meaning |
| --- | --- |
| `watch_paths` | Directories for the optional daemon |
| `quarantine_dir` | Blocked originals (`~/.phylor/quarantine`) |
| `notifications` | Desktop alerts on block |
| `fail_closed_on_suspicious` | Quarantine keyword hits when LLM is unavailable |
| `llm.enabled` | Local Ollama judging |
| `llm.endpoint` | Default `http://127.0.0.1:11434` |
| `llm.model` | Default `llama-guard3` |
| `llm.timeout_ms` | Judge HTTP ceiling (default `3000`) |

Content stays local unless you set `llm.endpoint` to a remote service.

## Enforcement

Quarantine and honeypot writes apply only to regular files. Symbolic links are refused to avoid TOCTOU path hijacks. The watcher skips symlinks; `--enforce` reports an error if asked to rewrite one.

Blocked originals move to `~/.phylor/quarantine/`. Phylor then writes a honeypot at the original path: a short Markdown notice that instructs the agent not to run setup, network, or credential steps, and to tell the user that Phylor blocked a suspected supply-chain payload. That keeps the IDE from depending on a missing file while still surfacing the alert in chat.

## Linux fanotify (optional)

```bash
cargo build --release --features fanotify
sudo ./target/release/phylor daemon --fanotify
```

Requires `CAP_SYS_ADMIN`. Phylor's own PID is allowed; content is read from the kernel-provided descriptor; threats receive `FAN_DENY` before honeypot installation; the LLM is not used on the blocked open path. Support outside native Linux filesystems (for example some WSL and container mounts) is limited.

## Project layout

```
Phylor/
├── rules/agent_skills.yar
├── fixtures/
├── src/
│   ├── exec.rs              # Preflight + agent/IDE launch
│   ├── pipeline.rs          # Detection cascade
│   ├── discover.rs          # Multi-agent skill / MCP path discovery
│   ├── fsutil.rs            # Symlink-safe path checks
│   ├── normalize.rs         # Unicode sanitizer
│   ├── markdown.rs          # Plaintext extraction
│   ├── cache.rs             # SHA-256 verdict LRU
│   ├── scan/                # Static engine + optional Ollama judge
│   ├── watch/               # File watcher (+ optional fanotify)
│   ├── enforce.rs           # Quarantine + honeypot
│   ├── alert.rs
│   └── service.rs
└── tests/
```

## Development

```bash
cargo test
cargo run -- scan fixtures/malicious_mcp.json
cargo run -- scan fixtures/malicious_remote_hydration.md
cargo run -- scan fixtures/safe_skill.md
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities in Phylor through a private GitHub security advisory. Do not publish working exploit details against Phylor until coordinated disclosure is complete.

Treat third-party skills and MCP servers as untrusted input, and keep agent auto-approve settings conservative.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Maurice Osoro.
