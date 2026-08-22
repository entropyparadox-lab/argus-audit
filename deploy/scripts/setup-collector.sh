#!/usr/bin/env bash
set -euo pipefail

echo "=== [Argus Audit] Central Collector Setup ==="

# 1. Build release binaries
cargo build --release -p argus-collector -p argus-cli

# 2. Install binaries to /usr/local/bin
sudo install -m 755 target/release/argus-collector /usr/local/bin/argus-collector
sudo install -m 755 target/release/argus /usr/local/bin/argus

# 3. Create sandboxed directory with strict 0700 permissions
sudo mkdir -p /var/log/argus
sudo chmod 700 /var/log/argus

# 4. Install systemd service
sudo install -m 644 deploy/systemd/argus-collector.service /etc/systemd/system/argus-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now argus-collector

echo "=== Collector is active and running on :19532 ==="
echo "Check status with: sudo systemctl status argus-collector"
echo "Query sessions with: argus --db /var/log/argus/audit.db sessions"
