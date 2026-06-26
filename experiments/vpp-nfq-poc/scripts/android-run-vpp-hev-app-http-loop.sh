#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: repeat Android app-process HTTP through VpnService -> VPP -> HEV.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-142.251.13.94}"
PORT="${PORT:-80}"
CYCLES="${CYCLES:-3}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-7}"
STOP_WAIT="${STOP_WAIT:-3}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-hev-app-http-loop.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SOCKS_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server-loop.log"
APP_HTTP_LOG="/data/user/0/$PACKAGE/files/logs/app-http-probe.log"
VPP_CLI_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-cli.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/socks-loop.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/socks-loop.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/socks-loop.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/socks-loop.pid'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPP HEV app HTTP loop"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "host=$HOST"
echo "port=$PORT"
echo "cycles=$CYCLES"

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$SOCKS_LOG' '$REMOTE_ROOT/runtime/socks-loop.pid'"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_su "chmod 755 '$REMOTE_SERVER'; nohup '$REMOTE_SERVER' >'$SOCKS_LOG' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/socks-loop.pid'"
sleep 1

echo
echo "## socks server"
adb_su "cat '$REMOTE_ROOT/runtime/socks-loop.pid'; cat '$SOCKS_LOG'" | tr -d '\r'

for i in $(seq 1 "$CYCLES"); do
  echo
  echo "## cycle $i start"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
  adb_su "rm -f '$APP_HTTP_LOG' '$VPP_CLI_LOG' '$HEV_LOG' /data/user/0/$PACKAGE/files/vpp/logs/vpp-shim.log"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez start true --es mode vpp-hev
  sleep "$START_WAIT"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez appHttpProbe true --es host "$HOST" --ei port "$PORT" --es path "/loop-$i"
  sleep "$PROBE_WAIT"

  echo
  echo "### app-http-probe.log"
  app_log="$(adb_su "cat '$APP_HTTP_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$app_log"

  if ! grep -q 'HTTP/1.0 200 OK' <<<"$app_log"; then
    echo "cycle $i expected app HTTP 200 via SOCKS smoke server" >&2
    exit 1
  fi

  socks_count="$(adb_su "grep -c 'connect $HOST:$PORT' '$SOCKS_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1)"
  socks_count="${socks_count:-0}"
  echo "socks_connect_count=$socks_count"
  if [ "$socks_count" -lt "$i" ]; then
    echo "cycle $i expected SOCKS connect count >= $i, got $socks_count" >&2
    exit 1
  fi

  echo
  echo "### stop"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true
  sleep "$STOP_WAIT"

  echo
  echo "### vpp cli tail"
  adb_su "tail -n 32 '$VPP_CLI_LOG' 2>/dev/null || true" | tr -d '\r'

  echo
  echo "### hev log"
  hev_log="$(adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$hev_log"
  if grep -E 'free\\(\\): invalid size|Fatal signal|SIGABRT' <<<"$hev_log" >/dev/null; then
    echo "cycle $i saw HEV fatal pattern" >&2
    exit 1
  fi

  adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
  sleep 1
  leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
  if [ -n "$leftovers" ]; then
    echo "cycle $i left vpp process:" >&2
    printf '%s\n' "$leftovers" >&2
    exit 1
  fi
  echo "cycle $i ok"
done

echo
echo "## final socks log"
adb_su "cat '$SOCKS_LOG' 2>/dev/null || true" | tr -d '\r'

echo
echo "ok: android vpp-hev app HTTP loop"
