#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify Android VpnService -> packaged VPP worker handoff -> HEV.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-142.251.13.94}"
PORT="${PORT:-80}"
BLOCK_IP4_DST="${BLOCK_IP4_DST:-}"
REDIRECT_THREAD="${REDIRECT_THREAD:-}"
EXPECT_DROP="${EXPECT_DROP:-0}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-7}"
STOP_WAIT="${STOP_WAIT:-3}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-hev-handoff-poc.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SOCKS_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server-handoff.log"
APP_HTTP_LOG="/data/user/0/$PACKAGE/files/logs/app-http-probe.log"
VPP_CLI_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-cli.log"
VPP_STDOUT_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-stdout.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/socks-handoff.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/socks-handoff.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/socks-handoff.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/socks-handoff.pid'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPP HEV worker handoff POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "host=$HOST"
echo "port=$PORT"
echo "block_ip4_dst=$BLOCK_IP4_DST"
echo "redirect_thread=$REDIRECT_THREAD"
echo "expect_drop=$EXPECT_DROP"

if [[ "$BUILD_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$SOCKS_LOG' '$REMOTE_ROOT/runtime/socks-handoff.pid'"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_su "chmod 755 '$REMOTE_SERVER'; nohup '$REMOTE_SERVER' >'$SOCKS_LOG' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/socks-handoff.pid'"
sleep 1

echo
echo "## socks server"
adb_su "cat '$REMOTE_ROOT/runtime/socks-handoff.pid'; cat '$SOCKS_LOG'" | tr -d '\r'

adb_su "rm -f '$APP_HTTP_LOG' '$VPP_CLI_LOG' '$VPP_STDOUT_LOG' '$HEV_LOG' /data/user/0/$PACKAGE/files/vpp/logs/vpp-shim.log"

before_count="$(adb_su "grep -c 'connect $HOST:$PORT' '$SOCKS_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1)"
before_count="${before_count:-0}"
echo "socks_count_before=$before_count"

echo
echo "## start vpp-hev-handoff"
start_args=(shell am start -n "$PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-handoff \
  --es allowedPackage "$PACKAGE")
if [[ -n "$BLOCK_IP4_DST" ]]; then
  start_args+=(--es blockIp4Dst "$BLOCK_IP4_DST")
fi
if [[ -n "$REDIRECT_THREAD" ]]; then
  start_args+=(--ei redirectThread "$REDIRECT_THREAD")
fi
adb_cmd "${start_args[@]}"
sleep "$START_WAIT"

echo
echo "## app HTTP probe"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appHttpProbe true \
  --es host "$HOST" \
  --ei port "$PORT" \
  --es path "/vpp-hev-handoff"
sleep "$PROBE_WAIT"

echo
echo "## app-http-probe.log"
app_log="$(adb_su "cat '$APP_HTTP_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$app_log"

echo
echo "## vpp-cli.log"
vpp_cli="$(adb_su "cat '$VPP_CLI_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$vpp_cli"

echo
echo "## vpp stdout tail"
adb_su "tail -n 80 '$VPP_STDOUT_LOG' 2>/dev/null || true" | tr -d '\r'

echo
echo "## hev log"
hev_log="$(adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$hev_log"

after_count="$(adb_su "grep -c 'connect $HOST:$PORT' '$SOCKS_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1)"
after_count="${after_count:-0}"
echo "socks_count_after=$after_count"

echo
echo "## stop"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true
sleep "$STOP_WAIT"

if [[ "$EXPECT_DROP" == "1" ]]; then
  if grep -q 'HTTP/1.0 200 OK' <<<"$app_log"; then
    echo "expected app HTTP to be blocked by VPP worker" >&2
    exit 1
  fi
  if [[ "$after_count" -ne "$before_count" ]]; then
    echo "expected no new SOCKS connect when VPP worker drops" >&2
    exit 1
  fi
  if [[ -n "$BLOCK_IP4_DST" ]] && ! grep -q "block-ip4-dst $BLOCK_IP4_DST" <<<"$vpp_cli"; then
    echo "expected VPP block-ip4-dst $BLOCK_IP4_DST in CLI log" >&2
    exit 1
  fi
  if ! grep -Eq 'blocked [1-9]' <<<"$vpp_cli"; then
    echo "expected VPP blocked counter to increase" >&2
    exit 1
  fi
else
  if ! grep -q 'HTTP/1.0 200 OK' <<<"$app_log"; then
    echo "expected app HTTP 200 through vpp-hev-handoff" >&2
    exit 1
  fi
  if [[ "$after_count" -le "$before_count" ]]; then
    echo "expected SOCKS connect count to increase" >&2
    exit 1
  fi
fi
if ! grep -q 'mode handoff-forward-fd' <<<"$vpp_cli"; then
  echo "expected VPP tun_poc mode handoff-forward-fd" >&2
  exit 1
fi
if ! grep -Eq 'handoff target-thread 1 .* worker-packets [1-9]' <<<"$vpp_cli"; then
  echo "expected VPP handoff worker packets on target thread 1" >&2
  exit 1
fi
if ! grep -Eq 'thread-hits worker-probe last 1 .* t1 [1-9]' <<<"$vpp_cli"; then
  echo "expected worker-probe thread hit on VPP worker 1" >&2
  exit 1
fi
if [[ -n "$REDIRECT_THREAD" ]]; then
  if ! grep -Eq 'redirect enabled 1 target-thread '"$REDIRECT_THREAD"' .* enqueued [1-9].* worker-packets [1-9]' <<<"$vpp_cli"; then
    echo "expected VPP redirect counters on target thread $REDIRECT_THREAD" >&2
    exit 1
  fi
  if ! grep -Eq 'thread-hits worker-redirect last '"$REDIRECT_THREAD"' .* t'"$REDIRECT_THREAD"' [1-9]' <<<"$vpp_cli"; then
    echo "expected worker-redirect thread hit on VPP worker $REDIRECT_THREAD" >&2
    exit 1
  fi
fi
if grep -E 'free\(\): invalid size|Fatal signal|SIGABRT' <<<"$hev_log" >/dev/null; then
  echo "saw HEV fatal pattern" >&2
  exit 1
fi

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
sleep 1
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -n "$leftovers" ]]; then
  echo "left vpp process:" >&2
  printf '%s\n' "$leftovers" >&2
  exit 1
fi

echo
if [[ "$EXPECT_DROP" == "1" ]]; then
  echo "ok: Android vpp-hev-handoff dropped app HTTP in VPP worker handoff"
else
  echo "ok: Android vpp-hev-handoff forwarded app HTTP through VPP worker handoff"
fi
