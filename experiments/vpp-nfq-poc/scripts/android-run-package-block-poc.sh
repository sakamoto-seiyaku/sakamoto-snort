#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: package name -> UID rule -> VPP NFQUEUE block smoke.

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 PACKAGE" >&2
  exit 2
fi

PACKAGE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
RULES_JSON="${RULES_JSON:-/tmp/sakamoto-package-block-rules.json}"
EVENT_LOG="${EVENT_LOG:-$REMOTE_ROOT/logs/nfq-package-block-poc.ndjson}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-package-block-poc.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"

cleanup() {
  local uid=""
  uid="$(python3 -c "import json; print(json.load(open('$RULES_JSON'))['rules'][0]['uid'])" 2>/dev/null || true)"
  if [ -n "$uid" ]; then
    adb_su "while iptables -w -D OUTPUT -o lo -p icmp -d 127.0.0.1 -m owner --uid-owner $uid -j NFQUEUE --queue-num 42 --queue-bypass 2>/dev/null; do :; done" >/dev/null 2>&1 || true
  fi
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' nfqueue-poc disable" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/vpp.pid'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

{
  echo "# Android package block POC"
  echo "adb_serial=$(adb_target_desc)"
  echo "package=$PACKAGE"

  "$SCRIPT_DIR/android-package-rules-json.sh" "$PACKAGE" "$RULES_JSON"
  python3 -m json.tool "$RULES_JSON"

  app_uid="$(python3 -c "import json; print(json.load(open('$RULES_JSON'))['rules'][0]['uid'])")"
  cli_cmd="$("$SCRIPT_DIR/poc-rules-to-vppctl.py" "$RULES_JSON" --event-log "$EVENT_LOG")"
  echo "app_uid=$app_uid"
  echo "generated_cli=$cli_cmd"

  echo
  echo "## start VPP"
  SKIP_PUSH="${SKIP_PUSH:-1}" STOP_AFTER=0 "$SCRIPT_DIR/android-run-vpp-minimal.sh"

  echo
  echo "## configure VPP"
  adb_su "rm -f '$EVENT_LOG'"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $cli_cmd" | tr -d '\r'

  echo
  echo "## install package UID owner rule"
  adb_su "iptables -w -I OUTPUT 1 -o lo -p icmp -d 127.0.0.1 -m owner --uid-owner $app_uid -j NFQUEUE --queue-num 42 --queue-bypass"
  adb_su "iptables -w -S OUTPUT | grep -- '--uid-owner $app_uid' || true" | tr -d '\r'

  echo
  echo "## ping as package UID"
  set +e
  adb_su "su $app_uid -c /system/bin/ping -c 3 -W 1 127.0.0.1" 2>&1 | tr -d '\r'
  ping_rc=${PIPESTATUS[0]}
  set -e
  echo "ping_rc=$ping_rc"

  sleep 1

  echo
  echo "## counters"
  counters="$(adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' show nfqueue-poc" | tr -d '\r')"
  printf '%s\n' "$counters"

  echo
  echo "## events"
  events="$(adb_su "cat '$EVENT_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$events"

  event_count="$(printf '%s\n' "$events" | grep -c '^{' || true)"
  uid_count="$(printf '%s\n' "$events" | grep -c "\"uid\":$app_uid" || true)"
  block_count="$(printf '%s\n' "$events" | grep -c '"verdict":"block"' || true)"
  echo "event_count=$event_count uid_count=$uid_count block_count=$block_count"

  test "$ping_rc" -ne 0
  test "$event_count" -eq 3
  test "$uid_count" -eq 3
  test "$block_count" -eq 3
  printf '%s\n' "$counters" | grep -q 'seen 3 accept 0 drop 3'
} 2>&1 | tee "$LOG"
