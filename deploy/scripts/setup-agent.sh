#!/usr/bin/env bash
set -euo pipefail

COLLECTOR_URL="${1:-http://cycorld-b650-livemixer.tail1dcdac.ts.net:19532}"

echo "=== [Argus Audit] Host Agent Setup ==="
echo "Target Collector URL: ${COLLECTOR_URL}"

# 1. Install binary
if [ -f target/release/argus-agent ]; then
    sudo install -m 755 target/release/argus-agent /usr/local/bin/argus-agent
else
    echo "Please build target/release/argus-agent or place the binary in this directory."
fi

# 2. Configure Global Profile Hook (/etc/profile.d/argus-agent.sh)
cat << 'EOF' | sudo tee /etc/profile.d/argus-agent.sh > /dev/null
# Argus Audit Auto-Wrapper for Interactive Sessions
if [ -z "${ARGUS_ACTIVE:-}" ] && [ -n "${PS1:-}" ] && [ -t 0 ]; then
    export ARGUS_ACTIVE=1
    export ARGUS_COLLECTOR_URL="http://cycorld-b650-livemixer.tail1dcdac.ts.net:19532"
    exec /usr/local/bin/argus-agent wrap --collector "${ARGUS_COLLECTOR_URL}"
fi
EOF

sudo chmod 644 /etc/profile.d/argus-agent.sh

echo "=== Agent installed and configured ==="
echo "Next interactive login will be automatically wrapped and audited."
