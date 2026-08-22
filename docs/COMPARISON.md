# ⚖️ Argus Audit vs. Industry Alternatives

A comprehensive technical and architectural comparison of **Argus Audit** against enterprise Privilege Access Management (PAM), session recording tools, eBPF security runtimes, and Linux audit daemons.

---

## 📊 High-Level Comparison Matrix

| Feature / Capability | **Argus Audit 🛡️** | **Teleport (Gravitational)** | **CyberArk / BeyondTrust** | **Sysdig Falco / Tetragon** | **Linux auditd / Snoopy** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Primary Focus** | **Dev & AI Agent Audit** | Infrastructure Access / PAM | Enterprise Compliance / PAM | Kernel Runtime Security | Basic OS Syscall Logging |
| **CPU / RAM Overhead** | **< 0.1% / < 8MB** | Moderate (~2-5% CPU) | High (Heavy agent/video) | Low (~1% CPU) | Low (~0.5% CPU) |
| **Terminal Latency** | **0 ms (Zero overhead)** | Low (~5-20ms proxy lag) | High (RDP/VNC lag) | N/A (Non-interactive) | 0 ms |
| **AI Agent Prompt Linker** | **✅ Native (Claude Code)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Prompt Drift / Injection Guard** | **✅ Built-in** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Storage Optimization** | **Input-Only (<500KB/day)** | Full Stream (~10-50MB/day) | Video RDP (~1GB/day) | Syslog alerts only | High (Raw audit logs) |
| **100% Paste & Code Blocks** | **✅ Full fidelity** | ✅ Yes | ✅ Yes | ❌ Fragmented | ❌ Truncated / Escaped |
| **Cryptographic Hash Chaining** | **✅ SHA256 Merkle Chain** | ✅ Yes | Proprietary | ❌ No | ❌ No (Mutable files) |
| **Client-Side Secret DLP** | **✅ In-Flight Masking** | ❌ Server-side only | ⚠️ Heavy OCR/DLP | ❌ No | ❌ No (Leaks secrets) |
| **Live Peeking & Remote Kill** | **✅ SSE Stream & Kill** | ✅ Moderated Sessions | ✅ Session Kill | ❌ Alert only | ❌ No |
| **Process Tree Lineage** | **✅ Full Hierarchy** | ⚠️ Limited | ❌ No | ✅ Full eBPF Tree | ❌ Flat syscalls |
| **Deployment Model** | **Standalone Single Binary** | Multi-node Proxy cluster | Heavy Windows Gateway | eBPF Kernel probes | OS daemon |
| **OS Support** | **Linux & macOS (Universal)** | Linux & Mac | Windows, Linux, Mac | Linux only (eBPF) | Linux only |
| **License** | **Apache-2.0 (Open Source)** | AGPLv3 / Commercial | Commercial Closed-Source | Apache-2.0 | GPL / Apache |

---

## 🔍 In-Depth Architectural Differentiators

### 1. Zero-Overhead "Input-Only" PTY vs. Traditional Full-Stream Recording
* **Traditional Approach (Teleport, Script, CyberArk)**:
  * Records both `stdin` (input) and `stdout/stderr` (output).
  * **Problem**: Running `cat large_file.csv` or compiling a project (`cargo build`, `npm install`) dumps hundreds of megabytes of garbage compiler output into the audit log, blowing up disk space and network bandwidth.
* **Argus Audit Approach**:
  * PTY master intercepts only `stdin` (human typing, clipboard pastes, AI agent prompt submissions).
  * `stdout` is directly passed through to the developer's screen at hardware speed without being stored.
  * **Result**: **95%+ storage reduction** (1 developer active 8 hours generates only ~200KB of compressed JSONL).

---

### 2. AI Coding Agent (Claude Code) Semantic Traceability
* **The Emerging Blindspot**:
  * Modern developers frequently run AI coding agents (`Claude Code`, `Codex`, `Aider`, `Hermes`) inside dev servers.
  * Standard PAM tools only see a deluge of bash commands (e.g. `sed`, `git`, `python`, `rm`) without knowing *why* they were executed.
* **Argus Audit Approach**:
  * Automatically extracts natural-language developer prompts from local agent session files (`history.jsonl`, `~/.claude/projects/`).
  * Time-aligns user prompts with concrete shell executions and process trees.
  * **Prompt Drift & Injection Detection**: Identifies if an AI agent executed unauthorized destructive actions (`rm -rf`) or external exfiltration (`curl http://c2`) that diverge from the original benign prompt.

---

### 3. Cryptographic Tamper-Evidence (Hash-Chained Audit Trail)
* **The Root Compromise Problem**:
  * In standard `auditd` or syslog setups, once an attacker achieves `root` privilege, they execute `rm -rf /var/log/*` or modify audit log lines to erase evidence.
* **Argus Audit Approach**:
  * Real-time append-only streaming over encrypted Tailscale/WireGuard.
  * Every audit event is chained with the previous event's SHA256 hash (`GENESIS -> Event 1 -> Event 2 -> ...`).
  * If an attacker gains DB access on the collector and deletes or edits an event, running `argus verify <session_id>` immediately flags mathematical tampering.

---

### 4. Client-Side Secret Redaction (DLP)
* **The Credential Ingestion Problem**:
  * When developers paste `.env` files, AWS Access Keys, or private SSH keys into terminals, audit systems usually log them in plain text, turning the audit store into a massive target for attackers.
* **Argus Audit Approach**:
  * `argus-agent` scans input buffers in real-time before network streaming.
  * Credentials are replaced with tokenized redaction markers (`[REDACTED:AWS_KEY]`, `[REDACTED:PRIVATE_KEY]`) while the local shell receives the unmodified bytes for seamless developer execution.

---

## 🎯 Positioning Summary

| Use Case | Best Choice | Why |
| :--- | :--- | :--- |
| **Engineering Dev Servers & AI Coding Workflows** | **Argus Audit** | Zero terminal latency, Input-only storage efficiency, Claude Code prompt-to-syscall tracing, and frictionless deployment. |
| **Enterprise Identity SSO & Multi-Cloud Bastion** | **Teleport** | When you require web-based Zero Trust access proxies for Kubernetes, Databases, and SSH in one unified gateway. |
| **Live Kernel Threat Detection & Container Runtime** | **Falco / Tetragon** | When you need real-time eBPF alerting for zero-day exploits in Kubernetes production pods without developer identity context. |
