# Argus Audit 🛡️

**Zero-Overhead Linux Dev & AI Activity Audit Engine in Rust**

[![Crates.io](https://img.shields.io/badge/crates.io-argus--audit-orange.svg)](https://crates.io/crates/argus-audit)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Argus Audit is a modern, high-performance Linux auditing engine designed specifically for developer environments and AI coding workflows (Claude Code, AI CLI agents).

---

## ⚡ Key Capabilities

* **Identity Resolution in Shared Accounts**: Trace individual developer identities by cryptographically linking SSH public keys to session TTYs.
* **Input-Only Capture (95%+ Storage Reduction)**: Record human/AI keystrokes and multiline pastes without saving gigabytes of noisy compiler/build outputs.
* **100% Paste & Long Prompt Fidelity**: Full-precision capture of multiline code blocks, `.env` edits, and Claude Code prompts.
* **Kernel-Level Tamper Resistance**: eBPF / Kernel audit with immutable flags (`-e 2`) to capture `execve`, sensitive file writes (`/etc/shadow`, `authorized_keys`), and outbound connections.
* **Real-time Append-Only Streaming**: Low-latency Zstd compressed streaming over Tailscale/WireGuard. Local root compromise cannot destroy remote forensic records.
* **LLM Semantic Analyzer**: Automatically roll up thousands of raw syscalls into clear, human-readable action narratives and detect anomalies.

---

## 🏗️ Architecture

```
  [ Dev Server (argus-agent) ]                    [ Collector (argus-collector) ]
┌───────────────────────────────┐               ┌─────────────────────────────────┐
│ • PTY Stdin-only Interceptor  │ ────────────> │ • Tokio/Axum HTTP2 Zstd Stream  │
│ • eBPF Kernel Probe (execve)  │  (Tailscale)  │ • SQLite / DuckDB Ingest        │
│ • SSH Identity Resolver       │               │ • LLM Semantic Analyzer Engine  │
└───────────────────────────────┘               └─────────────────────────────────┘
```

---

## 📦 Crates

* `crates/argus-common`: Core event types, schema definitions, and compression codecs.
* `crates/argus-agent`: Zero-overhead host audit agent and PTY interceptor.
* `crates/argus-collector`: High-throughput ingestion daemon.
* `crates/argus-analyzer`: LLM-assisted semantic behavior summarizer.
* `crates/argus-cli`: Terminal viewer, replay engine, and query CLI.

---

## 📜 License

Apache-2.0
