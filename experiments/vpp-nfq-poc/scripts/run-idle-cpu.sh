#!/usr/bin/env bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-42}"
PEER_IP="${PEER_IP:-10.200.42.2}"
HOST_IF="${HOST_IF:-nfq-host}"
SAMPLES="${SAMPLES:-5}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$POC_DIR/build/nfq-smoke"
LOG_DIR="$POC_DIR/results"
SMOKE_LOG="$LOG_DIR/nfq-smoke-idle-cpu.log"
CPU_LOG="$LOG_DIR/idle-cpu.log"

if [ ! -x "$BIN" ]; then
  "$SCRIPT_DIR/build-smoke.sh" >/dev/null
fi

mkdir -p "$LOG_DIR"
"$SCRIPT_DIR/setup-netns.sh" up

smoke_pid=""
cleanup() {
  if [ -n "$smoke_pid" ] && kill -0 "$smoke_pid" >/dev/null 2>&1; then
    kill -INT "$smoke_pid" >/dev/null 2>&1 || true
    wait "$smoke_pid" >/dev/null 2>&1 || true
  fi
  "$SCRIPT_DIR/setup-netns.sh" down
}
trap cleanup EXIT

"$BIN" --queue "$QUEUE_NUM" --mode accept-all --print-every 5 >"$SMOKE_LOG" 2>&1 &
smoke_pid="$!"

sleep 1

{
  echo "idle samples"
  for _ in $(seq 1 "$SAMPLES"); do
    ps -L -p "$smoke_pid" -o pid,tid,psr,pcpu,comm
    sleep 1
  done

  echo
  echo "active ping"
  ping -I "$HOST_IF" -c 5 -W 1 "$PEER_IP" || true

  echo
  echo "post-active samples"
  for _ in $(seq 1 "$SAMPLES"); do
    ps -L -p "$smoke_pid" -o pid,tid,psr,pcpu,comm
    sleep 1
  done
} | tee "$CPU_LOG"

echo
echo "cpu log: $CPU_LOG"
echo "nfq-smoke log: $SMOKE_LOG"
