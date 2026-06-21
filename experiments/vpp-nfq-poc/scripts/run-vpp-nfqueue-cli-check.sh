#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_DIR/build-root/install-vpp-native/vpp}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/nfqueue-poc-startup.conf}"
VPP_RUNTIME_ROOT="${VPP_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfq-poc}"
CLI_SOCK="$VPP_RUNTIME_ROOT/cli.sock"
LOG_DIR="$POC_DIR/results"
VPP_STDOUT_LOG="$LOG_DIR/vpp-nfqueue-cli-check.log"

if [ ! -x "$VPP_BIN" ]; then
  echo "VPP binary not found or not executable: $VPP_BIN" >&2
  exit 1
fi

if [ ! -x "$VPPCTL_BIN" ]; then
  echo "vppctl binary not found or not executable: $VPPCTL_BIN" >&2
  exit 1
fi

mkdir -p "$LOG_DIR" "$VPP_RUNTIME_ROOT/vpp-run"
rm -f "$CLI_SOCK" "$VPP_RUNTIME_ROOT/vpp.log"

vpp_pid=""
cleanup() {
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$VPP_BIN" -c "$VPP_CONFIG" >"$VPP_STDOUT_LOG" 2>&1 &
vpp_pid="$!"

for _ in $(seq 1 50); do
  if [ -S "$CLI_SOCK" ]; then
    break
  fi
  if ! kill -0 "$vpp_pid" >/dev/null 2>&1; then
    echo "VPP exited before CLI socket appeared" >&2
    cat "$VPP_STDOUT_LOG" >&2 || true
    exit 1
  fi
  sleep 0.1
done

if [ ! -S "$CLI_SOCK" ]; then
  echo "VPP CLI socket did not appear: $CLI_SOCK" >&2
  cat "$VPP_STDOUT_LOG" >&2 || true
  exit 1
fi

"$VPPCTL_BIN" -s "$CLI_SOCK" show plugins | grep -E 'nfqueue_poc|Plugin path'
"$VPPCTL_BIN" -s "$CLI_SOCK" show nfqueue-poc

echo
echo "vpp stdout log: $VPP_STDOUT_LOG"
