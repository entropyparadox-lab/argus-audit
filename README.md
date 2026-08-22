<div align="center">

# 🛡️ Argus Audit

**Zero-Overhead Linux & macOS Dev & AI Activity Audit Engine in Pure Rust**

*From Prompt to Kernel Syscall — Trace Developer & AI Agent Activity with Mathematical Tamper-Evidence.*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Features](#-key-features) • [Architecture](#-architecture) • [Quickstart](#-5-minute-quickstart) • [CLI Usage](#-cli-commands) • [Comparison](docs/COMPARISON.md) • [Contributing](CONTRIBUTING.md)

</div>

---

## ⚡ Why Argus Audit?

Traditional session recorders and audit daemons suffer from two fatal flaws in modern development environments:
1. **The Output Flood**: Recording both `stdin` and `stdout` creates gigabytes of compiler logs (`cargo build`, `npm install`), blowing up storage and network bandwidth.
2. **The AI Agent Blindspot**: When developers run AI CLI agents (`Claude Code`, `Codex`, `Hermes`), standard PAM tools only see hundreds of fragmented shell commands without understanding the developer's high-level intent or detecting prompt injection.

**Argus Audit solves this with a zero-overhead Rust architecture:**
* **Input-Only PTY Interception**: Captures human typing, multiline pastes, and prompt submissions while passing stdout directly to screen (95%+ storage reduction, <500KB/dev/day).
* **Identity Attribution in Shared Accounts**: Cryptographically links individual SSH public key fingerprints to interactive TTY sessions on shared accounts (`ubuntu`, `dev`).
* **AI Prompt-to-Syscall Traceability**: Extracts Claude Code natural-language prompts and correlates them with concrete process executions and process tree lineages.
* **Cryptographic Hash Chaining**: Formats every event into a SHA256 Merkle chain (`prev_hash -> hash`), making database tampering mathematically impossible to conceal.
* **In-Flight Secret DLP**: Automatically masks AWS keys, OpenAI tokens, and private SSH certificates before network transmission.
* **Live Peeking & Remote Kill**: Real-time SSE streaming to observe active sessions and instantly terminate dangerous activity remotely.

---

## 🏗️ Architecture

```
[ Developer Machine / Dev Server (argus-agent) ]             [ Central Monitoring Server (argus-collector) ]
┌──────────────────────────────────────────────┐              ┌─────────────────────────────────────────┐
│ • PTY Stdin Interceptor (Input & Paste only) │ ───────────> │ • Tokio/Axum HTTP/2 Ingestion Daemon    │
│ • SSH Key Fingerprint & Identity Resolver    │  (Zstd Stream│ • Real-time Zstd Decompression          │
│ • In-Flight Secret Redaction (Client DLP)    │  over Wire-  │ • SQLite WAL Store with 0700 Sandboxing │
│ • Claude Code AI Session Prompt Extractor    │   Guard)     │ • SHA256 Hash Chain Integrity Verifier  │
└──────────────────────────────────────────────┘              └────────────────────┬────────────────────┘
                                                                                   │
                                                              [ Operator CLI & AI Engine (argus-cli) ]
                                                              ┌────────────────────▼────────────────────┐
                                                              │ • argus live <id>   (Real-time SSE Peeker)│
                                                              │ • argus replay <id> (Speed-controlled play)│
                                                              │ • argus tree <id>   (Process Hierarchy) │
                                                              │ • argus verify <id> (Tamper Verification)│
                                                              │ • argus analyze <id>(AI Semantic Rollup)│
                                                              └─────────────────────────────────────────┘
```

---

## 🚀 5-Minute Quickstart

### 1. Build and Run Central Collector (on Central Server / Mac)
```bash
# Clone the repository
git clone https://github.com/entropyparadox-lab/argus-audit.git
cd argus-audit

# Build release binaries
cargo build --release -p argus-collector -p argus-cli

# Start collector daemon (listening on 0.0.0.0:19532)
./target/release/argus-collector run --bind 0.0.0.0:19532 --db /var/log/argus/audit.db
```

### 2. Wrap Interactive Session with Host Agent (on Target Host)
```bash
# Build agent binary
cargo build --release -p argus-agent

# Launch audited shell session streaming to collector
./target/release/argus-agent wrap --collector "http://your-collector-ip:19532"
```

---

## 💻 CLI Commands

The unified `argus` CLI provides complete observability over all developer and AI sessions:

### List Recorded Sessions
```bash
argus sessions --limit 20
```
```text
SESSION ID                            TIMESTAMP (UTC)       USER     CLIENT IP        SSH KEY / COMMENT        DURATION
-----------------------------------------------------------------------------------------------------------------------------
c9b1f2e0-7d34-4b5c-89a1-5629c1234567  2026-08-22 14:10:00  ubuntu   192.168.1.50     dev_kim@company.com      142.5s
```

### Live Peeking (Real-Time Observation via SSE)
```bash
argus live <SESSION_UUID>
```

### Keystroke & Input Replay (with Speed Control)
```bash
# Real-time replay
argus replay <SESSION_UUID> --speed 1.0

# 3x speed playback
argus replay <SESSION_UUID> --speed 3.0
```

### Process Tree Lineage
```bash
argus tree <SESSION_UUID>
```
```text
=== Process Tree Lineage (Session: c9b1f2e0-...) ===
├── bash (PID: 1201) -> bash
│   └── python (PID: 1205) -> python build.py
│       └── cargo (PID: 1206) -> cargo test --all
```

### Cryptographic Tamper Verification
```bash
argus verify <SESSION_UUID>
# Output: ✓ Session c9b1f2e0-...: Cryptographic hash chain verified. (No tampering detected)
```

### Emergency Force-Kill
```bash
argus kill <SESSION_UUID>
```

### AI Semantic Analysis & Prompt Drift Detection
```bash
argus analyze <SESSION_UUID> --claude-history ~/.claude/history.jsonl
```

---

## 📊 Comparison with Existing Tools

For a detailed technical comparison against **Teleport, CyberArk, BeyondTrust, Falco/Tetragon, and Linux auditd**, see **[docs/COMPARISON.md](docs/COMPARISON.md)**.

---

## 📦 Workspace Crates

| Crate | Description |
| :--- | :--- |
| **`crates/argus-common`** | Core event schemas, Zstd stream codecs, and SHA256 cryptographic hash-chain engine. |
| **`crates/argus-agent`** | Zero-overhead PTY Stdin-only interceptor, SSH identity resolver, and in-flight secret DLP. |
| **`crates/argus-collector`** | High-throughput Axum HTTP/2 ingestion server, SQLite WAL store, and SSE live broadcaster. |
| **`crates/argus-analyzer`** | Claude Code prompt parser, process tree builder, and AI Prompt-to-Syscall Drift detector. |
| **`crates/argus-cli`** | Comprehensive operator CLI tool (`sessions`, `live`, `replay`, `tree`, `verify`, `kill`, `analyze`). |

---

## 🛡️ Security & Privacy

* **Append-Only Remote Logging**: Even if an attacker gains root privilege on the target machine, logs already streamed to the collector cannot be modified or deleted.
* **Storage Sandboxing**: Collector stores database files with strict `0700`/`0600` permissions.
* **In-Flight DLP**: Secrets matching patterns (AWS, OpenAI, GitHub, Private Keys) are automatically masked before leaving the host memory.

---

## 📜 License

Licensed under the **Apache License, Version 2.0** ([LICENSE](LICENSE)).
