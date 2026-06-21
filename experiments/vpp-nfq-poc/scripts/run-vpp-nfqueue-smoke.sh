#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-accept-all}"
QUEUE_NUM="${QUEUE_NUM:-42}"
PEER_IP="${PEER_IP:-10.200.42.2}"
HOST_IF="${HOST_IF:-nfq-host}"
COUNT="${COUNT:-20}"

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
LOG="$LOG_DIR/vpp-nfqueue-smoke-${MODE//[^A-Za-z0-9_.-]/_}.log"
VPP_STDOUT_LOG="$LOG_DIR/vpp-nfqueue-smoke-${MODE//[^A-Za-z0-9_.-]/_}-vpp.log"

if [ ! -x "$VPP_BIN" ]; then
  echo "VPP binary not found or not executable: $VPP_BIN" >&2
  exit 1
fi

if [ ! -x "$VPPCTL_BIN" ]; then
  echo "vppctl binary not found or not executable: $VPPCTL_BIN" >&2
  exit 1
fi

case "$MODE" in
  accept-all)
    cli_mode="mode accept-all"
    ;;
  drop-all)
    cli_mode="mode drop-all"
    ;;
  drop-ratio=*)
    ratio="${MODE#drop-ratio=}"
    cli_mode="mode drop-ratio $ratio"
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

mkdir -p "$LOG_DIR" "$VPP_RUNTIME_ROOT/vpp-run"
rm -f "$CLI_SOCK" "$VPP_RUNTIME_ROOT/vpp.log"
exec > >(tee "$LOG") 2>&1

vpp_pid=""
cleanup() {
  if [ -S "$CLI_SOCK" ]; then
    "$VPPCTL_BIN" -s "$CLI_SOCK" nfqueue-poc disable >/dev/null 2>&1 || true
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  "$SCRIPT_DIR/setup-netns.sh" down
}
trap cleanup EXIT

"$SCRIPT_DIR/setup-netns.sh" up

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

echo "enable command: nfqueue-poc enable queue $QUEUE_NUM $cli_mode"
"$VPPCTL_BIN" -s "$CLI_SOCK" nfqueue-poc enable queue "$QUEUE_NUM" $cli_mode
"$VPPCTL_BIN" -s "$CLI_SOCK" show nfqueue-poc

echo
echo "ping -I $HOST_IF -c $COUNT -W 1 $PEER_IP"
set +e
ping -I "$HOST_IF" -c "$COUNT" -W 1 "$PEER_IP"
ping_rc=$?
set -e

echo
"$VPPCTL_BIN" -s "$CLI_SOCK" show nfqueue-poc
echo "ping_rc=$ping_rc"

stats_line="$(grep '^seen ' "$LOG" | tail -n 1)"
seen="$(awk '{ print $2 }' <<<"$stats_line")"
accepted="$(awk '{ print $4 }' <<<"$stats_line")"
dropped="$(awk '{ print $6 }' <<<"$stats_line")"

case "$MODE" in
  accept-all)
    if [ "$ping_rc" -ne 0 ]; then
      echo "accept-all expected ping success, got rc=$ping_rc" >&2
      exit 1
    fi
    if [ "$accepted" -eq 0 ] || [ "$dropped" -ne 0 ]; then
      echo "accept-all expected accepts and no drops, got seen=$seen accept=$accepted drop=$dropped" >&2
      exit 1
    fi
    ;;
  drop-all)
    if [ "$ping_rc" -eq 0 ]; then
      echo "drop-all expected ping failure, got rc=0" >&2
      exit 1
    fi
    if [ "$dropped" -eq 0 ] || [ "$accepted" -ne 0 ]; then
      echo "drop-all expected drops and no accepts, got seen=$seen accept=$accepted drop=$dropped" >&2
      exit 1
    fi
    ;;
  drop-ratio=*)
    echo "drop-ratio observed seen=$seen accept=$accepted drop=$dropped ping_rc=$ping_rc"
    ;;
esac

echo
echo "vpp nfqueue smoke log: $LOG"
echo "vpp stdout log: $VPP_STDOUT_LOG"
