#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: Android upstream failure, Wi-Fi handover, and recovery behavior.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST4="${HOST4:-142.251.13.94}"
HOST6="${HOST6:-2606:4700:4700::1111}"
PORT="${PORT:-80}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-network-recovery-poc}"
BUILD="${BUILD:-0}"
INSTALL="${INSTALL:-0}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-5-network-recovery-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"
APP_HTTP_LOG="files/logs/app-http-probe.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
PROTECT_LOG="files/vpp/logs/vpp-protect.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

wifi_was_disabled=0

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null | tr -d '\r' || true
}

stop_app() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
}

stop_server() {
  adb_cmd shell "if [ -f '$SERVER_PID' ]; then kill -TERM \$(cat '$SERVER_PID') 2>/dev/null || true; fi; rm -f '$SERVER_PID'" >/dev/null 2>&1 || true
}

start_server() {
  adb_cmd shell mkdir -p "$REMOTE_ROOT"
  adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
  adb_cmd shell chmod 755 "$REMOTE_SERVER"
  adb_cmd shell "nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! >'$SERVER_PID'"
  sleep 1
}

capture() {
  local name="$1"
  local http="$2"
  local protect="$3"
  local hev="$4"
  {
    echo "### $name"
    echo "timestamp=$(date +%s)"
    echo "wifi=$(adb_cmd shell cmd wifi status 2>/dev/null | tr -d '\r')"
    echo "routes4=$(adb_cmd shell ip route show | tr -d '\r')"
    echo "routes6=$(adb_cmd shell ip -6 route show | tr -d '\r')"
    echo "app_pid=$(adb_cmd shell pidof "$PACKAGE" | tr -d '\r')"
    echo "vpp_pid=$(adb_cmd shell pidof vpp | tr -d '\r')"
    echo "http=$http"
    echo "protect=$protect"
    echo "hev=$hev"
    echo "logcat=$(adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r')"
  } >"$RESULT_DIR/$name.txt"
}

request() {
  local family="$1"
  local host="$2"
  local name="$3"
  app_cmd rm -f "$APP_HTTP_LOG" "$HEV_LOG" "$PROTECT_LOG" >/dev/null 2>&1 || true
  local started
  started="$(date +%s)"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true --es host "$host" --ei port "$PORT" \
    --es path "/sakamoto-5-$name" >/dev/null
  sleep 6
  local finished
  finished="$(date +%s)"
  local http protect hev
  http="$(app_read "$APP_HTTP_LOG")"
  protect="$(app_read "$PROTECT_LOG")"
  hev="$(app_read "$HEV_LOG")"
  printf '%s\n' "$http" >"$RESULT_DIR/$name-http.log"
  printf '%s\n' "$protect" >"$RESULT_DIR/$name-protect.log"
  printf '%s\n' "$hev" >"$RESULT_DIR/$name-hev.log"
  capture "$name" "$http" "$protect" "$hev"
  echo "request=$name family=$family elapsed_ms_lower_bound=$(( (finished - started) * 1000 ))"
  printf '%s\n' "$http"
}

cleanup() {
  if [[ "$wifi_was_disabled" == "1" ]]; then
    adb_cmd shell svc wifi enable >/dev/null 2>&1 || true
    sleep 3
  fi
  stop_app
  stop_server
}
trap cleanup EXIT

echo "# SAKAMOTO-5 Android network recovery POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
echo "wifi_ipv4=$(adb_cmd shell ip -4 addr show wlan0 | tr -d '\r' | awk '/inet / {print $2; exit}')"
echo "wifi_ipv6=$(adb_cmd shell ip -6 addr show wlan0 | tr -d '\r' | awk '/scope global/ {print $2; exit}')"
echo "other_networks=$(adb_cmd shell 'ip -o link show | tr -d "\\r"' 2>/dev/null || true)"

if [[ "$BUILD" == "1" ]]; then
  "$SCRIPT_DIR/android-build-hev.sh"
  "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
stop_app
stop_server
start_server
adb_cmd shell rm -f "$SERVER_LOG"
stop_server
start_server

baseline4="$(adb_cmd shell ip route show | tr -d '\r')"
baseline6="$(adb_cmd shell ip -6 route show | tr -d '\r')"
printf '%s\n' "$baseline4" >"$RESULT_DIR/baseline-routes4.txt"
printf '%s\n' "$baseline6" >"$RESULT_DIR/baseline-routes6.txt"

start_vpn() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true --ez enableIpv6 true \
    --es mode vpp-hev-owner-resolver \
    --es allowedPackage "$PACKAGE" --ei blockOwnerUid 112540 >/dev/null
  sleep 5
}

start_vpn
request ip4 "$HOST4" baseline-ip4
request ip6 "$HOST6" baseline-ip6

echo "## proxy unavailable: stop SOCKS server"
stop_server
request ip4 "$HOST4" proxy-unavailable
if grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/proxy-unavailable-http.log"; then
  echo "proxy-unavailable unexpectedly succeeded" >&2
  exit 1
fi
adb_cmd shell pidof "$PACKAGE" >"$RESULT_DIR/proxy-unavailable-app-pid.txt"
adb_cmd shell pidof vpp >"$RESULT_DIR/proxy-unavailable-vpp-pid.txt"

start_server
request ip4 "$HOST4" proxy-recovered-ip4
request ip6 "$HOST6" proxy-recovered-ip6
grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/proxy-recovered-ip4-http.log"
grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/proxy-recovered-ip6-http.log"

echo "## short blackhole: pause SOCKS server after listen"
server_pid="$(adb_cmd shell cat "$SERVER_PID" | tr -d '\r')"
adb_cmd shell kill -STOP "$server_pid"
request ip4 "$HOST4" short-blackhole
if grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/short-blackhole-http.log"; then
  echo "short-blackhole unexpectedly succeeded" >&2
  exit 1
fi
adb_cmd shell kill -CONT "$server_pid"
request ip4 "$HOST4" blackhole-recovered
grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/blackhole-recovered-http.log"

echo "## Wi-Fi disconnect/reconnect"
adb_cmd shell svc wifi disable
wifi_was_disabled=1
sleep 5
adb_cmd shell ip route show >"$RESULT_DIR/wifi-off-routes4.txt"
adb_cmd shell ip -6 route show >"$RESULT_DIR/wifi-off-routes6.txt"
request ip4 "$HOST4" wifi-off
if grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/wifi-off-http.log"; then
  echo "wifi-off unexpectedly succeeded" >&2
  exit 1
fi
adb_cmd shell pidof "$PACKAGE" >"$RESULT_DIR/wifi-off-app-pid.txt"
adb_cmd shell pidof vpp >"$RESULT_DIR/wifi-off-vpp-pid.txt"

adb_cmd shell svc wifi enable
wifi_was_disabled=0
sleep 8
start_server
request ip4 "$HOST4" wifi-recovered-ip4
request ip6 "$HOST6" wifi-recovered-ip6
grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/wifi-recovered-ip4-http.log"
grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/wifi-recovered-ip6-http.log"

adb_cmd shell cat "$SERVER_LOG" >"$RESULT_DIR/socks-server.log"
adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS >"$RESULT_DIR/final-processes.txt"
adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' >"$RESULT_DIR/final-logcat.txt"
echo "PASS: proxy unavailable, blackhole, Wi-Fi off/on, and IPv4/IPv6 recovery"
echo "result_dir=$RESULT_DIR"
