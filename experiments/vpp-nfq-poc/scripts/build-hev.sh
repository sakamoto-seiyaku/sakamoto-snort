#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
HEV_DIR="${HEV_DIR:-$VPP_WORK_ROOT/hev-socks5-tunnel}"
JOBS="${JOBS:-$(nproc)}"

if [ ! -d "$HEV_DIR/.git" ]; then
  "$SCRIPT_DIR/fetch-hev.sh"
fi

git config --global --add safe.directory "$HEV_DIR" >/dev/null 2>&1 || true
git config --global --add safe.directory "$HEV_DIR/src/core" >/dev/null 2>&1 || true
git config --global --add safe.directory "$HEV_DIR/third-part/hev-task-system" >/dev/null 2>&1 || true
git config --global --add safe.directory "$HEV_DIR/third-part/lwip" >/dev/null 2>&1 || true
git config --global --add safe.directory "$HEV_DIR/third-part/yaml" >/dev/null 2>&1 || true

make -C "$HEV_DIR" -j "$JOBS" shared

echo "HEV shared library:"
ls -lh "$HEV_DIR/bin/libhev-socks5-tunnel.so"
