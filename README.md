# Phylor

User-space pre-execution guardrail for AI coding agent skills, rules, and MCP configs.

Phylor inspects instruction files (`SKILL.md`, `.mdc` rules, MCP JSON, and related paths) for supply-chain style payloads before you trust them in Cursor, Claude Code, or similar agents. The default workflow does **not** require root or a kernel driver.

This is **v0.2** — clone, build, and run locally. There is no hosted installer yet.

## Design stance

Kernel file blockers (Linux `fanotify`, macOS Endpoint Security, Windows minifilters) are powerful but poorly suited to a portable open-source tool: they need elevated privileges or vendor entitlements, behave inconsistently in WSL2 and Dev Containers, and ask developers to trust a root daemon to protect an unprivileged IDE.

Phylor therefore centers on:

1. **`phylor exec`** — preflight-scan the workspace, then launch the IDE
2. **`phylor scan` / `init`** — on-demand and retroactive checks
3. **Optional user-level watcher** — best-effort notify daemon (no root)
4. **Experimental Linux fanotify** — documented separately; not the default path

## What it detects

| Layer | Coverage |
| --- | --- |
| Unicode / Policy A | Tags block, bidi spoofing, dense zero-width abuse |
| Markdown plaintext | Emphasis/HTML fragmentation before static matching |
| Static rules | Shell pipes, credential exfil, obfuscation, agent tool coercion |
| MCP configs | Dangerous `command` / `args` patterns (eval, `child_process`, `curl\|bash`) |
| Remote hydration | Fetch remote text and inject it into agent context |
| Optional LLM | Local Ollama judge for ambiguous prompt injection (CLI / notify only) |

**Known gaps:** multi-file split payloads, runtime tool proxying, and fully dynamic remote stages still need deeper gateway work. Phylor is a mitigation, not a sandbox.

## Requirements

- Rust **1.88+** (stable)
- Optional: [Ollama](https://ollama.com) for semantic judging

## Install (build from source)

```bash
git clone https://github.com/MauriceOS/Phylor.git
cd Phylor
cargo build --release
```

Binary: `target/release/phylor` (`phylor.exe` on Windows).

### Windows

```powershell
cargo build --release
.\target\release\phylor.exe init
.\target\release\phylor.exe exec -- cursor .
```

### macOS / Linux

```bash
cargo build --release
./target/release/phylor init
./target/release/phylor exec -- cursor .
# or: ./target/release/phylor exec -- claude
```

## Quick start

```bash
# Discover paths, write ~/.phylor/config.toml, retroactive scan
phylor init
phylor init --enforce

# Recommended daily driver: preflight then launch
phylor exec -- cursor .
phylor exec --enforce -- cursor .

# One-off scan (skills, rules, or MCP JSON)
phylor scan path/to/SKILL.md
phylor scan .cursor/mcp.json --enforce

# Optional background watcher (user-level; no root)
phylor daemon
```

`phylor exec` without `--enforce` exits with code `2` if threats are found and does not launch the command.

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

Scanning stays on-machine unless you point `llm.endpoint` elsewhere.

## Enforcement safety

Quarantine/honeypot refuses symbolic links and re-checks the path before write, reducing symlink TOCTOU hijacks during atomic swap. Symlinked “skills” are skipped by the watcher and reported as errors under `--enforce`.

When a file is quarantined, Phylor writes a honeypot at the original path so the agent can warn the user in-chat. Originals remain under `~/.phylor/quarantine/`.

## Optional Linux fanotify

```bash
cargo build --release --features fanotify
sudo ./target/release/phylor daemon --fanotify
```

Experimental only. Requires `CAP_SYS_ADMIN`. Self-PID is allowed to avoid deadlocks; analysis uses the kernel FD; threats are `FAN_DENY`’d before honeypot write; the LLM is never invoked under the blocked open. Not available on macOS/Windows, and unreliable for many WSL/Dev Container layouts.

## Project layout

```
Phylor/
├── rules/agent_skills.yar
├── fixtures/
├── src/
│   ├── exec.rs              # Preflight + IDE launch wrapper
│   ├── pipeline.rs          # Detection cascade
│   ├── discover.rs          # Skill / MCP path discovery
│   ├── fsutil.rs            # Symlink-safe path checks
│   ├── normalize.rs         # Unicode sanitizer
│   ├── markdown.rs          # Plaintext extraction
│   ├── cache.rs             # SHA-256 verdict LRU
│   ├── scan/                # Static engine + optional Ollama judge
│   ├── watch/               # User-space watcher (+ optional fanotify)
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

See [CONTRIBUTING.md](CONTRIBUTING.md). Useful areas: MCP coverage, false-positive reports with redacted samples, `phylor exec` UX, and CI packaging.

## Security

Report Phylor vulnerabilities via a private GitHub security advisory. Do not open public issues with working exploits against Phylor until coordinated disclosure is complete.

Keep agent auto-approve settings conservative. Treat third-party skills and MCP servers as untrusted input.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Maurice Osoro.
