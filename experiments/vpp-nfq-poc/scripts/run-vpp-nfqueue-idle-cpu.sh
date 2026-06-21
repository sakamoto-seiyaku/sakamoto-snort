#!/usr/bin/env bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-42}"
PEER_IP="${PEER_IP:-10.200.42.2}"
HOST_IF="${HOST_IF:-nfq-host}"
SAMPLES="${SAMPLES:-5}"
DELAY="${DELAY:-1}"
WARMUP="${WARMUP:-3}"
ACTIVE_COUNT="${ACTIVE_COUNT:-5}"

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
CPU_LOG="$LOG_DIR/vpp-nfqueue-idle-cpu.log"
VPP_STDOUT_LOG="$LOG_DIR/vpp-nfqueue-idle-cpu-vpp.log"

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
exec > >(tee "$CPU_LOG") 2>&1

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

"$VPPCTL_BIN" -s "$CLI_SOCK" nfqueue-poc enable queue "$QUEUE_NUM" mode accept-all
"$VPPCTL_BIN" -s "$CLI_SOCK" show nfqueue-poc

sleep "$WARMUP"
clk_tck="$(getconf CLK_TCK)"

read_thread_ticks() {
  local tid="$1"
  awk '{ print $14 + $15 }' "/proc/$vpp_pid/task/$tid/stat"
}

read_thread_comm() {
  local tid="$1"
  cat "/proc/$vpp_pid/task/$tid/comm"
}

sample_threads() {
  local label="$1"

  echo
  echo "$label"
  for _ in $(seq 1 "$SAMPLES"); do
    mapfile -t tids < <(/usr/bin/find "/proc/$vpp_pid/task" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
    start_ns="$(date +%s%N)"
    declare -A start_ticks=()
    for tid in "${tids[@]}"; do
      start_ticks["$tid"]="$(read_thread_ticks "$tid")"
    done

    sleep "$DELAY"

    end_ns="$(date +%s%N)"
    elapsed_ns=$((end_ns - start_ns))
    printf '%8s %8s %8s %s\n' PID TID CPU% COMMAND
    for tid in "${tids[@]}"; do
      if [ ! -r "/proc/$vpp_pid/task/$tid/stat" ]; then
        continue
      fi
      end_ticks="$(read_thread_ticks "$tid")"
      delta_ticks=$((end_ticks - ${start_ticks[$tid]}))
      cpu_pct="$(awk -v ticks="$delta_ticks" -v clk="$clk_tck" -v ns="$elapsed_ns" 'BEGIN { printf "%.3f", (ticks / clk) / (ns / 1000000000) * 100 }')"
      printf '%8s %8s %8s %s\n' "$vpp_pid" "$tid" "$cpu_pct" "$(read_thread_comm "$tid")"
    done
  done
}

echo "vpp_pid=$vpp_pid"
echo "warmup_seconds=$WARMUP delay_seconds=$DELAY clk_tck=$clk_tck"
sample_threads "idle samples with nfqueue-poc enabled"

echo
echo "active ping"
ping -I "$HOST_IF" -c "$ACTIVE_COUNT" -W 1 "$PEER_IP" || true
"$VPPCTL_BIN" -s "$CLI_SOCK" show nfqueue-poc

sample_threads "post-active idle samples with nfqueue-poc enabled"

echo
echo "cpu log: $CPU_LOG"
echo "vpp log: $VPP_STDOUT_LOG"
