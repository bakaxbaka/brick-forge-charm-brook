#!/bin/bash
set -u
cd /workspace/bitcoin-forensics/analysis
export PYTHONUNBUFFERED=1
export RESULTS_DIR=/results
export CACHE_DIR=/workspace/bitcoin-forensics/cache
mkdir -p /results "$CACHE_DIR/blocks"
while true; do
  python3 -u scan_nonce_reuse.py --start 210000 --end 220000 --output /results/nonce_reuse.json \
    >>/results/scan.log 2>&1
  code=$?
  last=$(python3 -c "import json;print(json.load(open('/results/progress.json')).get('last_completed_height',0))" 2>/dev/null || echo 0)
  echo "[supervisor] scanner exit=$code last_completed_height=$last" >>/results/scan.log
  if [ "${last:-0}" -ge 220000 ]; then
    echo "[supervisor] complete" >>/results/scan.log
    exit 0
  fi
  sleep 3
done
