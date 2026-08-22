# Contributing to Argus Audit 🛡️

Thank you for your interest in contributing to Argus Audit! We welcome all contributions from bug reports to new feature PRs, documentation, and performance benchmarks.

---

## 🛠️ Development Setup

### Prerequisites
* **Rust toolchain** (1.75+ or latest stable)
* **Linux** (kernel 5.4+) or **macOS** (Apple Silicon / Intel)
* `sqlite3` and `zstd` development libraries

### Clone & Build
```bash
git clone https://github.com/entropyparadox-lab/argus-audit.git
cd argus-audit

# Build all workspace crates
cargo build --all

# Run all unit and integration tests
cargo test --all
```

---

## 🏗️ Workspace Architecture

* `crates/argus-common`: Core event types (`AuditEvent`, `SessionInit`, `KeystrokeInput`, etc.), codecs, and cryptographic hash chain verification.
* `crates/argus-agent`: Host daemon and PTY Stdin-only interceptor with client-side secret DLP.
* `crates/argus-collector`: High-throughput Axum HTTP/2 ingestion daemon, Zstd decompressor, and SQLite WAL engine with SSE live streaming.
* `crates/argus-analyzer`: Claude Code history parser, Process tree lineage builder, and AI Prompt-to-Syscall Drift detector.
* `crates/argus-cli`: Operator CLI tool (`argus sessions`, `argus live`, `argus replay`, `argus tree`, `argus verify`, `argus kill`, `argus analyze`).

---

## 📜 Pull Request Guidelines

1. **Format your code**: Always run `cargo fmt` before submitting.
2. **Lint**: Ensure `cargo clippy --all -- -D warnings` reports zero warnings.
3. **Tests**: Add unit or integration tests for any new features or bug fixes.
4. **Commit Conventions**: Use Conventional Commits (`feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`).
