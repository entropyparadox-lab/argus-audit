# Argus Audit: Zero-Overhead Linux Dev & AI Activity Audit Engine

> **"From Prompt to Kernel Syscall, Zero Overhead Dev & AI Activity Audit"**

---

## 1. Background & Problem Definition

### 1.1 Current Problem in Shared Dev Environments
* **Identity Blindspot**: Developers log into Linux development servers using a shared user account (`ubuntu`, `dev`) and a shared PEM key. There is no cryptographic way to identify who executed which command or edited which file.
* **Network L2 Limitation**: MAC addresses are stripped at the first router/gateway, making client identification via MAC impossible on L3/VPN networks.
* **Log Volatility & Forensics Risk**: When an attacker obtains `root` privileges (privilege escalation), they can easily delete local logs (`/var/log/*`, `journalctl --vacuum-time=0`), destroying all forensic evidence.
* **AI Agent Auditing Gap**: Developers increasingly use AI coding agents (`Claude Code`, `Codex`, etc.) inside servers. There is no structured bridge between the developer's high-level intent (natural language prompts) and the resulting shell commands/file changes.

---

## 2. Core Architecture & Design Principles

```
[ Target Dev Host (argus-agent) ]                           [ Central Log Server (argus-collector) ]
┌──────────────────────────────────────────────┐              ┌─────────────────────────────────────────┐
│ 1. SSH Key Identity Linker (~/.ssh/auth_keys)│              │                                         │
│ 2. PTY Stdin Interceptor (Input & Paste only)│ ───────────> │  Async Zstd Stream Receiver (Axum/HTTP2)│
│ 3. Kernel Syscall Probe (eBPF / execve)      │  (Tailscale  │  SQLite / DuckDB Event Store (chmod 700)│
│ 4. Prompt Extractor (Claude CLI session link)│   Encrypted) │                                         │
└──────────────────────────────────────────────┘              └────────────────────┬────────────────────┘
                                                                                   │
                                                              [ Semantic Intelligence (argus-analyzer) ]
                                                              ┌────────────────────▼────────────────────┐
                                                              │ • LLM Semantic Activity Rollup          │
                                                              │ • Prompt-to-Execution Consistency Check │
                                                              │ • Anomaly & Data Exfiltration Detection │
                                                              │ • Natural Language Hermes Search Agent  │
                                                              └─────────────────────────────────────────┘
```

### 2.1 Key Design Principles
1. **Zero-Overhead (<0.1% CPU, <10MB RAM)**: Written in pure Rust. No heavy runtime, zero memory leaks, no terminal latency (0ms).
2. **Input-Only Optimization (95%+ storage saving)**: Ignores stdout flood (build outputs, large `cat`, compiler logs). Captures only human/AI `stdin` input, keystrokes, and clipboard pastes.
3. **100% Paste & Long Prompt Capture**: Captures bracketed pastes, multiline SQL queries, `.env` edits, and long Claude prompts without truncation.
4. **Append-Only Remote Forwarding**: Real-time streaming over WireGuard/Tailscale. Even if the host machine is wiped or root is compromised, logs are already safely preserved on the collector.
5. **Kernel Security Hardening**: Immutable audit rules (`-e 2`), kernel module load monitoring, and sensitive file (`/etc/shadow`, `authorized_keys`) tamper traps.
6. **AI Agent Prompt-Syscall Traceability**: Automatically correlates developer natural-language prompts with concrete shell executions.

---

## 3. Crate Architecture

### 3.1 `argus-common`
* Shared event schemas, serialized with Serde/JSON/Bincode.
* `AuditEvent` enum:
  * `SessionInit`: SSH key fingerprint, client IP, username, TTY, timestamp.
  * `KeystrokeInput`: Raw stdin stream, timestamps, paste indicators.
  * `ProcessExec`: `execve` syscalls, argv, pid, ppid, uid, cwd.
  * `KernelAlert`: Sensitive file write, kernel module manipulation, network outbound.
  * `PromptTrace`: Extracted AI prompt, project context, session ID.

### 3.2 `argus-agent`
* Lightweight daemon running on monitored dev servers.
* PTY Proxy intercepting standard input for interactive user sessions.
* Kernel event listener (`kauditd` netlink or eBPF probe).
* Background ring-buffer with real-time Zstd compression and HTTP/2 streaming client.

### 3.3 `argus-collector`
* High-throughput central ingestion daemon running on the central monitoring server (`cycorld-b650`).
* Axum-based streaming ingestion endpoint over Tailscale.
* SQLite / DuckDB storage engine with daily partition and WAL mode.
* Strictly sandboxed storage (`chmod 700`, `root:root` access).

### 3.4 `argus-analyzer`
* Semantic rollup engine transforming raw syscall streams into human-readable action summaries.
* LLM analysis pipeline:
  * Prompt vs. Execution audit.
  * Suspicious script & exfiltration detection.
  * Secret leak identification in terminal streams.

### 3.5 `argus-cli`
* Operator CLI tool for interacting with Argus Audit:
  * `argus query --user <key> --since <time>`: Query activity by developer or time.
  * `argus replay --session <id>`: Play back terminal keystroke sessions in real-time.
  * `argus analyze --session <id>`: Trigger LLM semantic summary.

---

## 4. Verification & Testing Strategy

1. **Unit & Property Tests**: Serialization roundtrips, Zstd streaming compression/decompression, Ring-buffer backpressure.
2. **PTY Interception Smoke Test**: Verify typed keystrokes and multiline pastes (1KB ~ 100KB) are accurately captured without terminal lag.
3. **End-to-End Ingestion Verification**: Agent on host $\rightarrow$ Tailscale $\rightarrow$ Collector on central server $\rightarrow$ SQLite DB record validation.
4. **Stress & Benchmark**: 100,000 events/sec throughput test, measuring agent CPU (<0.1%) and memory usage (<10MB).
