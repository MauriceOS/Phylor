# Phylor

Pre-execution guardrail for AI coding agent skills, rules, and MCP configs.

Phylor inspects instruction files (`SKILL.md`, `.mdc` rules, MCP JSON, and related paths) for supply-chain payloads before they are loaded by Cursor, Claude Code, and similar agents.

**v0.2** — build from source. No hosted installer yet.

## How it works

Phylor runs in user space by default:

1. **`phylor exec`** — scan the workspace, then launch the IDE
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

# Preflight then launch
phylor exec -- cursor .
phylor exec --enforce -- cursor .

# One-off scan (skills, rules, or MCP JSON)
phylor scan path/to/SKILL.md
phylor scan .cursor/mcp.json --enforce

# Optional background watcher
phylor daemon
```

Without `--enforce`, `phylor exec` exits with code `2` if threats are found and does not launch the command.

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

Blocked originals move to `~/.phylor/quarantine/`. A honeypot replaces the original path so the agent can notify the user in-chat.

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
│   ├── exec.rs              # Preflight + IDE launch
│   ├── pipeline.rs          # Detection cascade
│   ├── discover.rs          # Skill / MCP path discovery
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
