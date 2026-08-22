# Argus Audit Deployment & Operation Guide

---

## 1. Central Collector Setup (This Server: `cycorld-b650-livemixer`)

### 1.1 Build & Service Activation
```bash
cd /home/cycorld/projects/argus-audit
cargo build --release -p argus-collector -p argus-cli

# Install binaries and systemd service
sudo ./deploy/scripts/setup-collector.sh
```

### 1.2 Verification
```bash
# Check collector service status
sudo systemctl status argus-collector

# Test health check over Tailscale
curl http://localhost:19532/health
# Response: OK
```

---

## 2. Monitored Target Deployment (Company Dev Server & macOS)

### 2.1 Linux Development Server (Ubuntu / Debian / RHEL)
1. **Build agent binary**:
   ```bash
   cargo build --release -p argus-agent
   ```
2. **Copy binary to target server**:
   ```bash
   scp target/release/argus-agent user@dev-server:/tmp/
   ```
3. **Run installation on target server**:
   ```bash
   sudo install -m 755 /tmp/argus-agent /usr/local/bin/argus-agent
   sudo ./deploy/scripts/setup-agent.sh http://cycorld-b650-livemixer.tail1dcdac.ts.net:19532
   ```

### 2.2 macOS (MacBook, Mac mini, Mac Studio)
1. **Build on macOS**:
   ```bash
   cargo build --release -p argus-agent
   sudo cp target/release/argus-agent /usr/local/bin/
   ```
2. **Add auto-wrap hook to `~/.zshrc`**:
   ```bash
   if [[ -z "$ARGUS_ACTIVE" && -t 0 ]]; then
       export ARGUS_ACTIVE=1
       exec /usr/local/bin/argus-agent wrap --collector "http://cycorld-b650-livemixer.tail1dcdac.ts.net:19532"
   fi
   ```

---

## 3. Operations & Audit Workflows

### 3.1 List Recent Developer Sessions
```bash
# Using direct SQLite DB on collector server:
argus --db /var/log/argus/audit.db sessions --limit 20

# Or querying remote collector over HTTP:
argus --collector http://cycorld-b650-livemixer.tail1dcdac.ts.net:19532 sessions
```

### 3.2 Real-time Keystroke & Input Replay
```bash
# Replay session in real-time (1x speed)
argus replay <SESSION_UUID> --speed 1.0

# Fast-forward replay (3x speed)
argus replay <SESSION_UUID> --speed 3.0

# Instant print
argus replay <SESSION_UUID> --speed 0
```

### 3.3 AI Assistance & Semantic Activity Analysis
```bash
# Analyze session and link with Claude Code prompts
argus analyze <SESSION_UUID> --claude-history ~/.claude/history.jsonl
```
