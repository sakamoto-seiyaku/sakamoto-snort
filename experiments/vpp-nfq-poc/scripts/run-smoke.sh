#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-accept-all}"
QUEUE_NUM="${QUEUE_NUM:-42}"
PEER_IP="${PEER_IP:-10.200.42.2}"
HOST_IF="${HOST_IF:-nfq-host}"
COUNT="${COUNT:-20}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$POC_DIR/build/nfq-smoke"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/nfq-smoke-${MODE//[^A-Za-z0-9_.-]/_}.log"

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

"$BIN" --queue "$QUEUE_NUM" --mode "$MODE" --print-every 5 >"$LOG" 2>&1 &
smoke_pid="$!"

sleep 1

set +e
ping -I "$HOST_IF" -c "$COUNT" -W 1 "$PEER_IP"
ping_rc=$?
set -e

sleep 1
kill -INT "$smoke_pid" >/dev/null 2>&1 || true
wait "$smoke_pid" >/dev/null 2>&1 || true
smoke_pid=""

echo
echo "nfq-smoke log: $LOG"
tail -n 40 "$LOG"

case "$MODE" in
  accept-all)
    if [ "$ping_rc" -ne 0 ]; then
      echo "accept-all expected ping success, got rc=$ping_rc" >&2
      exit 1
    fi
    ;;
  drop-all)
    if [ "$ping_rc" -eq 0 ]; then
      echo "drop-all expected ping failure, got rc=0" >&2
      exit 1
    fi
    ;;
  drop-ratio=*)
    echo "drop-ratio ping rc=$ping_rc; inspect loss percentage above."
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac
