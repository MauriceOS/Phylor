# Phylor

Pre-execution guardrail for AI coding agent skills and rules.

Phylor watches the directories where tools like Cursor, Claude Code, and similar agents load `SKILL.md`, `.mdc` rules, and related instruction files. When a new or modified file appears, Phylor inspects it **before it should be trusted**, and can quarantine malicious content so the agent does not execute supply-chain payloads hidden in Markdown.

This is **v0.1** — clone, build, and run locally. There is no hosted installer yet.

## Why it exists

Agent skills are plain Markdown with YAML front matter. They are treated as instructions, not as untrusted code. Traditional SAST tools largely ignore them. Attackers have already used malicious skills to push remote shell chains, credential theft, and invisible Unicode smuggling.

Phylor adds a local control point:

1. Watch known skill/rule directories (or scan on demand)
2. Sanitize steganographic Unicode and strip Markdown/HTML camouflage
3. Match static patterns (shell chains, credential exfil, agent tool coercion)
4. Optionally escalate ambiguous cases to a **local** LLM judge (Ollama; never under fanotify)
5. Quarantine the original file and replace it with a honeypot
6. Emit a desktop notification when something is blocked

## Threat coverage (v0.1)

| Layer | What it catches |
| --- | --- |
| Unicode / Policy A | Unicode Tags block (`U+E0000`–`U+E007F`), bidi spoofing, dense zero-width abuse |
| Markdown plaintext | Emphasis/HTML fragmentation such as `c**u**r*l*` before static matching |
| Static rules | Shell pipes, credential exfil, obfuscated decode chains, agent tool coercion |
| Keyword gate + LLM | Ambiguous prompt injection when Ollama is enabled (CLI / notify daemon only) |
| SHA-256 cache | Repeat opens of unchanged content short-circuit to allow |
| Enforcement | Quarantine + honeypot + OS notification |

**Honest limits:** On Windows and macOS (and Linux without elevated fanotify), Phylor uses a filesystem watcher plus locking. That shrinks the race window; it does not eliminate it the way Linux `fanotify` `FAN_OPEN_PERM` can. Kernel mode is experimental and Linux-only.

### Linux fanotify semantics

When built with `--features fanotify` and run as root:

1. Phylor's own PID is always allowed (prevents self-deadlock while writing honeypots).
2. Content is read from the kernel-provided file descriptor only.
3. Inspection uses the **fast** path (Unicode + demarkdown + static). No LLM while the opener is blocked.
4. Threats receive `FAN_DENY` immediately. The honeypot is written **after** deny so the blocked `open()` never observes a swapped inode. The IDE's next open sees the honeypot after mtime update.

## Requirements

- Rust **1.88+** (stable)
- Optional: [Ollama](https://ollama.com) if you want semantic judging
- Optional (Linux kernel interceptor): root / `CAP_SYS_ADMIN` and build with `--features fanotify`

## Install (build from source)

```bash
git clone https://github.com/MauriceOS/Phylor.git
cd Phylor
cargo build --release
```

The binary is at `target/release/phylor` (or `phylor.exe` on Windows).

Add it to your `PATH`, or run it via `cargo run --release -- <command>`.

### Platform notes

**Windows**

```powershell
cargo build --release
.\target\release\phylor.exe init
.\target\release\phylor.exe service install
# or run in the foreground:
.\target\release\phylor.exe daemon
```

Uses the notify-based watcher and Windows toast notifications. Scheduled Task registration is attempted via `schtasks` on `service install`.

**macOS**

```bash
cargo build --release
./target/release/phylor init
./target/release/phylor service install   # LaunchAgent
./target/release/phylor daemon           # foreground
```

**Linux**

```bash
cargo build --release
./target/release/phylor init
./target/release/phylor service install   # systemd --user
./target/release/phylor daemon
```

Kernel interceptor (experimental):

```bash
cargo build --release --features fanotify
sudo ./target/release/phylor daemon --fanotify
```

## Quick start

```bash
# 1) Discover agent skill paths, write ~/.phylor/config.toml, retroactive scan
phylor init

# Quarantine anything already malicious:
phylor init --enforce

# 2) Register a user-level background service (optional)
phylor service install

# 3) Or run the daemon in the foreground while developing Phylor itself
phylor daemon
```

One-off scan:

```bash
phylor scan path/to/SKILL.md
phylor scan path/to/SKILL.md --enforce
```

Show config:

```bash
phylor status
```

## Configuration

Default config path: `~/.phylor/config.toml`

Important knobs:

| Key | Meaning |
| --- | --- |
| `watch_paths` | Directories monitored by the daemon |
| `quarantine_dir` | Where blocked originals are moved (`~/.phylor/quarantine` by default) |
| `notifications` | Desktop alerts on block |
| `fail_closed_on_suspicious` | If `true`, keyword hits without LLM confirmation are quarantined |
| `llm.enabled` | Turn on local Ollama judging (notify/CLI paths only) |
| `llm.endpoint` | Default `http://127.0.0.1:11434` |
| `llm.model` | Default `llama-guard3` |
| `llm.timeout_ms` | Hard ceiling for judge HTTP calls (default `3000`) |

Skills never leave your machine for scanning unless **you** point `llm.endpoint` at a remote service.

## How blocking looks to the agent

When Phylor quarantines a file, it writes a honeypot at the original path. The honeypot tells the agent to stop setup/network/credential actions and to inform the user that Phylor blocked a suspected supply-chain payload. Quarantined originals stay under `~/.phylor/quarantine/`.

## Project layout

```
Phylor/
├── rules/agent_skills.yar   # Human-readable rule descriptions
├── fixtures/                # Malicious and benign samples for tests
├── src/
│   ├── pipeline.rs          # Detection cascade (fast vs full)
│   ├── normalize.rs         # Unicode / stego sanitizer
│   ├── markdown.rs          # Plaintext extraction for static scan
│   ├── cache.rs             # SHA-256 allow/block LRU
│   ├── keywords.rs          # Cheap LLM prefilter
│   ├── scan/                # Static engine + optional Ollama judge
│   ├── watch/               # notify daemon + Linux fanotify
│   ├── enforce.rs           # Quarantine + honeypot
│   ├── alert.rs             # Desktop notifications
│   └── service.rs           # User service registration
└── tests/                   # Integration tests over fixtures
```

The runtime static engine mirrors the intent of the `.yar` rules in-process (regex). That keeps builds light and Windows-friendly. Contributions to expand rules in both the `.yar` file and `src/scan/yara.rs` are welcome.

## Development

```bash
cargo test
cargo run -- scan fixtures/malicious_reverse_shell.md
cargo run -- scan fixtures/safe_skill.md
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs are welcome — especially rule coverage, platform service polish, and false-positive reports with redacted samples.

## Security

If you believe you have found a vulnerability in Phylor itself, open a private security advisory on the GitHub repository (or email the maintainers listed there). Do not file public issues with working exploit details against Phylor until coordinated disclosure is done.

Phylor is a **mitigation**, not a guarantee. Keep agent auto-approve settings conservative, and treat third-party skills as untrusted input.

## License

MIT — see [LICENSE](LICENSE).
