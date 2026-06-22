#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
HEV_DIR="${HEV_DIR:-$VPP_WORK_ROOT/hev-socks5-tunnel}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp/build-root/install-vpp-native/vpp}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/tun-poc-startup.conf}"
LOG_DIR="$POC_DIR/results"

if [ ! -x "$VPP_BIN" ]; then
  echo "VPP binary not found or not executable: $VPP_BIN" >&2
  exit 1
fi

if [ ! -x "$VPPCTL_BIN" ]; then
  echo "vppctl binary not found or not executable: $VPPCTL_BIN" >&2
  exit 1
fi

if [ ! -f "$HEV_DIR/bin/libhev-socks5-tunnel.so" ]; then
  "$SCRIPT_DIR/build-hev.sh"
fi

export LD_LIBRARY_PATH="$HEV_DIR/bin:$HEV_DIR/third-part/yaml/bin:$HEV_DIR/third-part/lwip/bin:$HEV_DIR/third-part/hev-task-system/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

python3 "$SCRIPT_DIR/run-vpp-tun-hev-smoke.py" \
  --hev-root "$HEV_DIR" \
  --vpp-bin "$VPP_BIN" \
  --vppctl-bin "$VPPCTL_BIN" \
  --vpp-config "$VPP_CONFIG" \
  --log-dir "$LOG_DIR"
