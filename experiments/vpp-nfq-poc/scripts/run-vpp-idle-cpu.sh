#!/usr/bin/env bash
set -euo pipefail

SAMPLES="${SAMPLES:-5}"
DELAY="${DELAY:-1}"
WARMUP="${WARMUP:-3}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$POC_DIR/results"
VPP_STDOUT_LOG="$LOG_DIR/vpp-minimal-startup.log"
CPU_LOG="$LOG_DIR/vpp-minimal-idle-cpu.log"

mkdir -p "$LOG_DIR"

vpp_pid=""
cleanup() {
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$SCRIPT_DIR/run-vpp-minimal.sh" >"$VPP_STDOUT_LOG" 2>&1 &
vpp_pid="$!"

sleep 2

if ! kill -0 "$vpp_pid" >/dev/null 2>&1; then
  echo "VPP exited before CPU sampling" >&2
  cat "$VPP_STDOUT_LOG" >&2 || true
  exit 1
fi

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

{
  echo "vpp_pid=$vpp_pid"
  echo "warmup_seconds=$WARMUP delay_seconds=$DELAY clk_tck=$clk_tck"
  echo "idle samples, instantaneous per thread"
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
} | tee "$CPU_LOG"

echo
echo "cpu log: $CPU_LOG"
echo "vpp log: $VPP_STDOUT_LOG"
