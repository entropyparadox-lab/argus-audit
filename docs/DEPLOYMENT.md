# 🌐 Argus Audit Deployment & Integration Guide

This guide covers production deployment topologies, host agent integration patterns, and zero-overhead observability setups for Linux servers, macOS developer workstations, and AI development environments.

---

## 📑 Table of Contents
1. [Deployment Topologies](#1-deployment-topologies)
   * [Topology A: Public HTTPS via Cloudflare Tunnel / Reverse Proxy (Zero-VPN)](#topology-a-public-https-via-cloudflare-tunnel--reverse-proxy-recommended)
   * [Topology B: Private Mesh VPN (Tailscale / WireGuard / VPC)](#topology-b-private-mesh-vpn-tailscale--wireguard--vpc)
   * [Topology C: Local / Air-Gapped Intranet](#topology-c-local--air-gapped-intranet)
2. [Central Collector Installation (`argus-collector`)](#2-central-collector-installation)
3. [Host Agent Integration (`argus-agent`)](#3-host-agent-integration)
   * [Pattern 1: Per-User Shell Integration (macOS & Linux)](#pattern-1-per-user-shell-integration)
   * [Pattern 2: Global System-Wide Enforcement (Shared Team Servers)](#pattern-2-global-system-wide-enforcement)
   * [Pattern 3: macOS Apple Silicon Code-Signing Requirement](#pattern-3-macos-apple-silicon-code-signing)
4. [Offline Resilience & Local Spooling](#4-offline-resilience--local-spooling)
5. [Verification & Day-2 Operations](#5-verification--day-2-operations)

---

## 1. Deployment Topologies

### Topology A: Public HTTPS via Cloudflare Tunnel / Reverse Proxy (Recommended)
Best for distributed engineering teams, remote developers, and multi-cloud environments without requiring a client VPN.

```
[ Developer Laptop / Cloud Instance ]
     │ (Standard Outbound HTTPS:443)
     ▼
[ Cloudflare Edge WAF / Reverse Proxy ] ➔ (e.g. https://audit.example.com)
     │ (Encrypted Tunnel / WireGuard)
     ▼
[ Central Collector Host (argus-collector:19532) ]
     └──► SQLite WAL Database (`audit.db`)
```

* **Zero Client VPN**: Works from any network, corporate firewall, home, or coffee shop.
* **WAF & DDoS Protection**: Edge layer absorbs untrusted traffic; only valid HTTPS POST batches reach the collector.

---

### Topology B: Private Mesh VPN (Tailscale / WireGuard / VPC)
Best for strictly private internal networks where nodes communicate across a private overlay network.

* **Collector URL**: `http://collector-node.tailscale-mesh.net:19532`
* Direct peer-to-peer WireGuard encrypted transit.

---

### Topology C: Local / Air-Gapped Intranet
Best for isolated compliance-critical labs and on-premise hardware clusters.

* **Collector URL**: `http://19532.internal.lan:19532` or `http://127.0.0.1:19532`

---

## 2. Central Collector Installation

The central collector is a single lightweight, zero-dependency Rust daemon.

### 2.1 Build Release Binary
```bash
git clone https://github.com/entropyparadox-lab/argus-audit.git
cd argus-audit
cargo build --release -p argus-collector -p argus-cli

sudo install -m 755 target/release/argus-collector /usr/local/bin/argus-collector
sudo install -m 755 target/release/argus-cli /usr/local/bin/argus
```

### 2.2 Systemd Service Setup (`/etc/systemd/system/argus-collector.service`)
```ini
[Unit]
Description=Argus Audit Central Log Ingestion Collector
After=network.target

[Service]
Type=simple
User=argus
Group=argus
ExecStart=/usr/local/bin/argus-collector run --bind 0.0.0.0:19532 --db /var/log/argus/audit.db
Restart=always
RestartSec=3s
LimitNOFILE=65536

# Security Sandboxing
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/argus
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
# Initialize storage directory with strict 0700 permissions
sudo mkdir -p /var/log/argus
sudo chown -R argus:argus /var/log/argus
sudo chmod 700 /var/log/argus

sudo systemctl daemon-reload
sudo systemctl enable --now argus-collector
```

### 2.3 Health Check
```bash
curl -i http://localhost:19532/health
# HTTP/1.1 200 OK
# OK
```

---

## 3. Host Agent Integration

The `argus-agent` acts as an ultra-low overhead PTY wrapper that intercepts keystrokes, pastes, and AI tool prompts without capturing high-volume stdout.

### Guard Clause Rule (Critical)
To ensure that non-interactive scripts, CI/CD runners, `scp`, `sftp`, `rsync`, and automation tools are **never blocked or wrapped**, always wrap the execution with interactive shell guards:

```bash
# Active TTY and non-empty prompt check
[[ -z "${ARGUS_ACTIVE:-}" && -t 0 && -n "${PS1:-}" ]]
```

---

### Pattern 1: Per-User Shell Integration

#### On Linux (`~/.bashrc` or `~/.zshrc`)
```bash
# Argus Audit Auto-Wrapper
if [ -z "${ARGUS_ACTIVE:-}" ] && [ -n "${PS1:-}" ] && [ -t 0 ]; then
    export ARGUS_ACTIVE=1
    export ARGUS_COLLECTOR_URL="https://audit.example.com"
    exec /usr/local/bin/argus-agent wrap --collector "${ARGUS_COLLECTOR_URL}"
fi
```

#### On macOS (`~/.zshrc`)
```zsh
# Argus Audit Auto-Wrapper
if [[ -z "${ARGUS_ACTIVE:-}" && -t 0 && -n "${PS1:-}" ]]; then
    export ARGUS_ACTIVE=1
    export ARGUS_COLLECTOR_URL="https://audit.example.com"
    exec /usr/local/bin/argus-agent wrap --collector "${ARGUS_COLLECTOR_URL}"
fi
```

---

### Pattern 2: Global System-Wide Enforcement (Shared Team Servers)

For shared bastion hosts and shared development servers where all developers log in via a shared account (e.g. `ubuntu`, `ec2-user`):

1. Place the wrapper script in `/etc/profile.d/argus-audit.sh`:
   ```bash
   sudo tee /etc/profile.d/argus-audit.sh << 'EOF'
   # Global Argus Audit Enforcement for Interactive Logins
   if [ -z "${ARGUS_ACTIVE:-}" ] && [ -n "${PS1:-}" ] && [ -t 0 ]; then
       export ARGUS_ACTIVE=1
       export ARGUS_COLLECTOR_URL="https://audit.example.com"
       exec /usr/local/bin/argus-agent wrap --collector "${ARGUS_COLLECTOR_URL}"
   fi
   EOF
   sudo chmod 644 /etc/profile.d/argus-audit.sh
   ```

---

### Pattern 3: macOS Apple Silicon Code-Signing

On macOS ARM64 (Apple Silicon), any compiled binary executed from a local path must possess a valid code signature. If building locally or deploying a cross-compiled binary, apply an ad-hoc signature:

```bash
# Apply ad-hoc local signature on macOS
codesign -s - -f /usr/local/bin/argus-agent
```

---

## 4. Offline Resilience & Local Spooling

For laptops operating in offline environments (flights, unstable connections), configure a local spooling path. `argus-agent` will buffer encrypted JSONL logs locally and automatically flush them to the central collector upon reconnection:

```bash
exec /usr/local/bin/argus-agent wrap \
    --collector "https://audit.example.com" \
    --spool "$HOME/.local/share/argus/spool.jsonl"
```

---

## 5. Verification & Day-2 Operations

Once nodes are transmitting sessions, audit operations can be conducted using the unified `argus` CLI.

### 5.1 List Active & Past Sessions
```bash
argus --db /var/log/argus/audit.db sessions --limit 20
```

### 5.2 Real-time Live Peeking (SSE)
Observe an ongoing suspicious session live as keystrokes are typed:
```bash
argus live <SESSION_UUID>
```

### 5.3 Keystroke & Input Replay
```bash
# Playback in real-time (1x)
argus replay <SESSION_UUID> --speed 1.0

# Instant terminal dump (0x)
argus replay <SESSION_UUID> --speed 0
```

### 5.4 Mathematical Tamper-Evidence Verification
Verify that neither raw database edits nor sequence omissions have occurred:
```bash
argus verify <SESSION_UUID>
# Output: ✓ Session <UUID>: Cryptographic hash chain verified. (No tampering detected)
```

### 5.5 AI Prompt-to-Syscall Semantic Analysis
```bash
argus analyze <SESSION_UUID> --claude-history ~/.claude/history.jsonl
```
This correlates Claude Code / AI agent prompts with the actual underlying commands executed, surfacing intent drift and prompt injection risks.
