#!/bin/bash
# Restart contract: dashboard on 8080 + nonce-reuse scanner if unfinished.
set -e
cd /workspace
mkdir -p /results /workspace/bitcoin-forensics/cache/blocks

# Dashboard
if ! curl -sf -o /dev/null --max-time 1 http://127.0.0.1:8080/ ; then
  nohup python3 -u /workspace/bitcoin-forensics/analysis/dashboard.py \
    >/results/dashboard.log 2>&1 &
  echo $! >/results/dashboard.pid
fi

# Scanner supervisor
last=0
if [ -f /results/progress.json ]; then
  last=$(python3 -c "import json;print(json.load(open('/results/progress.json')).get('last_completed_height',0))" 2>/dev/null || echo 0)
fi
if [ "${last:-0}" -lt 220000 ]; then
  if ! pgrep -f "scan_nonce_reuse.py" >/dev/null 2>&1; then
    nohup bash /workspace/bitcoin-forensics/analysis/run_scan.sh \
      >/results/supervisor.log 2>&1 &
    echo $! >/results/supervisor.pid
  fi
fi
exit 0
