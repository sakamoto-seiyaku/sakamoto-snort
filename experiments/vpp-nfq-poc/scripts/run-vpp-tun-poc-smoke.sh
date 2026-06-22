#!/usr/bin/env bash
set -euo pipefail

TUN_IF="${TUN_IF:-tun-poc0}"
TUN_ADDR="${TUN_ADDR:-198.18.0.1/24}"
REMOTE_IP="${REMOTE_IP:-198.18.0.2}"
TUN_FD="${TUN_FD:-3}"
COUNT="${COUNT:-5}"
MODE="${MODE:-reflect-icmp}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_DIR/build-root/install-vpp-native/vpp}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/tun-poc-startup.conf}"
VPP_RUNTIME_ROOT="${VPP_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfq-poc}"
CLI_SOCK="$VPP_RUNTIME_ROOT/cli.sock"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/vpp-tun-poc-smoke.log"
VPP_STDOUT_LOG="$LOG_DIR/vpp-tun-poc-smoke-vpp.log"

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
exec > >(tee "$LOG") 2>&1

vpp_pid=""
cleanup() {
  if [ -S "$CLI_SOCK" ]; then
    "$VPPCTL_BIN" -s "$CLI_SOCK" tun-poc disable >/dev/null 2>&1 || true
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  ip link del "$TUN_IF" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip link del "$TUN_IF" >/dev/null 2>&1 || true

"$SCRIPT_DIR/tun-vpp-wrapper.py" \
  --ifname "$TUN_IF" \
  --addr "$TUN_ADDR" \
  --fd "$TUN_FD" \
  -- "$VPP_BIN" -c "$VPP_CONFIG" >"$VPP_STDOUT_LOG" 2>&1 &
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

echo "enable command: tun-poc enable fd $TUN_FD mode $MODE"
"$VPPCTL_BIN" -s "$CLI_SOCK" tun-poc enable fd "$TUN_FD" mode "$MODE"
"$VPPCTL_BIN" -s "$CLI_SOCK" show tun-poc

echo
echo "ping -I $TUN_IF -c $COUNT -W 1 $REMOTE_IP"
set +e
ping -I "$TUN_IF" -c "$COUNT" -W 1 "$REMOTE_IP"
ping_rc=$?
set -e

echo
"$VPPCTL_BIN" -s "$CLI_SOCK" show tun-poc
echo "ping_rc=$ping_rc"

stats_line="$(grep '^rx ' "$LOG" | tail -n 1)"
rx_packets="$(awk '{ print $2 }' <<<"$stats_line")"
tx_packets="$(awk '{ print $6 }' <<<"$stats_line")"

if [ "$ping_rc" -ne 0 ]; then
  echo "reflect-icmp expected ping success, got rc=$ping_rc" >&2
  exit 1
fi

if [ "$rx_packets" -eq 0 ] || [ "$tx_packets" -eq 0 ]; then
  echo "expected VPP TUN rx/tx packets, got rx=$rx_packets tx=$tx_packets" >&2
  exit 1
fi

echo
echo "vpp tun smoke log: $LOG"
echo "vpp stdout log: $VPP_STDOUT_LOG"
