#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
HEV_DIR="${HEV_DIR:-$VPP_WORK_ROOT/hev-socks5-tunnel}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/hev-socketpair-probe.log"

if [ ! -f "$HEV_DIR/bin/libhev-socks5-tunnel.so" ]; then
  "$SCRIPT_DIR/build-hev.sh"
fi

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

export LD_LIBRARY_PATH="$HEV_DIR/bin:$HEV_DIR/third-part/yaml/bin:$HEV_DIR/third-part/lwip/bin:$HEV_DIR/third-part/hev-task-system/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

python3 "$SCRIPT_DIR/hev-socketpair-probe.py" --hev-root "$HEV_DIR"

echo
echo "hev socketpair probe log: $LOG"
