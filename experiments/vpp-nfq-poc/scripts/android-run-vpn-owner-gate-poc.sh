#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify VpnService owner UID lookup can gate VPP/HEV forwarding.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-142.251.13.94}"
PORT="${PORT:-80}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-7}"
STOP_WAIT="${STOP_WAIT:-3}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpn-owner-gate-poc.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SOCKS_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server-owner-gate.log"
APP_HTTP_LOG="/data/user/0/$PACKAGE/files/logs/app-http-probe.log"
VPP_CLI_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-cli.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"
GATE_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-owner-gate.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/socks-owner-gate.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/socks-owner-gate.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/socks-owner-gate.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/socks-owner-gate.pid'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPN owner gate POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "host=$HOST"
echo "port=$PORT"

if [[ "$BUILD_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
package_uid="$(awk -F'uid:' -v pkg="package:$PACKAGE" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
if [[ -z "$package_uid" ]]; then
  echo "failed to resolve package uid for $PACKAGE" >&2
  exit 1
fi
miss_uid=$((package_uid + 100000))
echo "package_uid=$package_uid"
echo "miss_uid=$miss_uid"

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$SOCKS_LOG' '$REMOTE_ROOT/runtime/socks-owner-gate.pid'"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_su "chmod 755 '$REMOTE_SERVER'; nohup '$REMOTE_SERVER' >'$SOCKS_LOG' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/socks-owner-gate.pid'"
sleep 1

socks_count() {
  adb_su "grep -c 'connect $HOST:$PORT' '$SOCKS_LOG' 2>/dev/null || true" |
    tr -d '\r' |
    tail -n 1
}

run_case() {
  local name="$1"
  local block_uid="$2"
  local expect="$3"
  local before_count
  local after_count

  echo
  echo "## case $name block_uid=$block_uid expect=$expect"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
  adb_su "rm -f '$APP_HTTP_LOG' '$VPP_CLI_LOG' '$HEV_LOG' '$GATE_LOG'"

  before_count="$(socks_count)"
  before_count="${before_count:-0}"
  echo "socks_count_before=$before_count"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-gate \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$block_uid"
  sleep "$START_WAIT"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true \
    --es host "$HOST" \
    --ei port "$PORT" \
    --es path "/owner-gate-$name"
  sleep "$PROBE_WAIT"

  echo
  echo "### app-http-probe.log"
  app_log="$(adb_su "cat '$APP_HTTP_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$app_log"

  echo
  echo "### owner gate log"
  gate_log="$(adb_su "cat '$GATE_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$gate_log"

  echo
  echo "### vpp cli tail"
  adb_su "tail -n 36 '$VPP_CLI_LOG' 2>/dev/null || true" | tr -d '\r'

  echo
  echo "### hev log"
  adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r'

  after_count="$(socks_count)"
  after_count="${after_count:-0}"
  echo "socks_count_after=$after_count"

  echo
  echo "### stop"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true
  sleep "$STOP_WAIT"

  if [[ "$expect" == "allow" ]]; then
    if ! grep -q 'HTTP/1.0 200 OK' <<<"$app_log"; then
      echo "case $name expected app HTTP 200" >&2
      exit 1
    fi
    if [[ "$after_count" -le "$before_count" ]]; then
      echo "case $name expected SOCKS connect count to increase" >&2
      exit 1
    fi
    if ! grep -Eq "gate forward .*ownerUid=$package_uid" <<<"$gate_log"; then
      echo "case $name expected gate forward ownerUid=$package_uid" >&2
      exit 1
    fi
  else
    if grep -q 'HTTP/1.0 200 OK' <<<"$app_log"; then
      echo "case $name expected HTTP to be blocked" >&2
      exit 1
    fi
    if [[ "$after_count" -ne "$before_count" ]]; then
      echo "case $name expected no new SOCKS connect" >&2
      exit 1
    fi
    if ! grep -Eq "gate drop .*ownerUid=$package_uid" <<<"$gate_log"; then
      echo "case $name expected gate drop ownerUid=$package_uid" >&2
      exit 1
    fi
  fi

  adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
  sleep 1
  leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
  if [[ -n "$leftovers" ]]; then
    echo "case $name left vpp process:" >&2
    printf '%s\n' "$leftovers" >&2
    exit 1
  fi
  echo "case $name ok"
}

run_case allow-miss "$miss_uid" allow
run_case block-hit "$package_uid" block

echo
echo "## final socks log"
adb_su "cat '$SOCKS_LOG' 2>/dev/null || true" | tr -d '\r'

echo
echo "ok: VPN owner UID gate forwards on miss and blocks on package UID hit"
