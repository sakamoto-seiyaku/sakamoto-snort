#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: prove every HEV SOCKS upstream socket is protected before connect.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-protect-poc}"
HOST4="${HOST4:-142.251.13.94}"
HOST6="${HOST6:-2606:4700:4700::1111}"
PORT="${PORT:-80}"
BUILD="${BUILD:-1}"
INSTALL="${INSTALL:-1}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-3-vpn-protect-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"
APP_HTTP_LOG="files/logs/app-http-probe.log"
VPP_CLI_LOG="files/vpp/logs/vpp-cli.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
PROTECT_LOG="files/vpp/logs/vpp-protect.log"
FORCE_FAILURE="files/force-protect-failure"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

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

cleanup() {
  app_cmd rm -f "$FORCE_FAILURE" >/dev/null 2>&1 || true
  stop_app
  stop_server
}
trap cleanup EXIT

server_accepts() {
  adb_cmd shell "grep -c '^.* accepted$' '$SERVER_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1
}

start_vpn() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-resolver \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid 112540 \
    --ez enableIpv6 true >/dev/null
  sleep 5
}

request() {
  local family="$1"
  local host="$2"
  local sequence="$3"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true \
    --es host "$host" \
    --ei port "$PORT" \
    --es path "/sakamoto-3-$family-$sequence" >/dev/null
  sleep 2
}

echo "# SAKAMOTO-3 VpnService protect POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "adb_identity=$(adb_cmd shell id | tr -d '\r')"
echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
echo "wlan4=$(adb_cmd shell ip -4 addr show wlan0 | tr -d '\r' | awk '/inet / {print $2; exit}')"
echo "route4=$(adb_cmd shell ip route get "$HOST4" | tr -d '\r')"
echo "route6=$(adb_cmd shell ip -6 route get "$HOST6" | tr -d '\r')"

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
adb_cmd shell mkdir -p "$REMOTE_ROOT"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_cmd shell chmod 755 "$REMOTE_SERVER"
adb_cmd shell "nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! >'$SERVER_PID'"
sleep 1

app_cmd rm -f "$APP_HTTP_LOG" "$VPP_CLI_LOG" "$HEV_LOG" "$PROTECT_LOG" \
  "$FORCE_FAILURE" >/dev/null
start_vpn

for i in 1 2 3; do
  request ip4 "$HOST4" "$i"
done
for i in 1 2 3; do
  request ip6 "$HOST6" "$i"
done
sleep 2

success_http="$(app_read "$APP_HTTP_LOG")"
success_protect="$(app_read "$PROTECT_LOG")"
success_vpp="$(app_read "$VPP_CLI_LOG")"
success_hev="$(app_read "$HEV_LOG")"
server_success="$(adb_cmd shell cat "$SERVER_LOG" | tr -d '\r')"
printf '%s\n' "$success_http" >"$RESULT_DIR/success-http.log"
printf '%s\n' "$success_protect" >"$RESULT_DIR/success-protect.log"
printf '%s\n' "$success_vpp" >"$RESULT_DIR/success-vpp-cli.log"
printf '%s\n' "$success_hev" >"$RESULT_DIR/success-hev.log"
printf '%s\n' "$server_success" >"$RESULT_DIR/success-socks-server.log"

http_ok_count="$(grep -c ' ok bytes=.*HTTP/1.0 200 OK' <<<"$success_http" || true)"
protect_ok_count="$(grep -c 'protect fd=.* result=1' <<<"$success_protect" || true)"
accept_count="$(server_accepts)"
echo "success_http_count=$http_ok_count"
echo "success_protect_count=$protect_ok_count"
echo "success_server_accept_count=$accept_count"
[[ "$http_ok_count" == "6" ]]
[[ "$protect_ok_count" == "6" ]]
[[ "$accept_count" == "6" ]]
grep -Fq "socks=$(adb_cmd shell ip -4 addr show wlan0 | tr -d '\r' | awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}'):41080" <<<"$success_hev"
if grep -Fq ':41080' <<<"$success_vpp"; then
  echo "SOCKS upstream recursively appeared in VPP TUN tuples" >&2
  exit 1
fi

stop_app
app_cmd rm -f "$APP_HTTP_LOG" "$VPP_CLI_LOG" "$HEV_LOG" "$PROTECT_LOG"
app_cmd touch "$FORCE_FAILURE"
before_failure="$(server_accepts)"
start_vpn
request forced-failure "$HOST4" 1
sleep 5

failure_http="$(app_read "$APP_HTTP_LOG")"
failure_protect="$(app_read "$PROTECT_LOG")"
failure_hev="$(app_read "$HEV_LOG")"
after_failure="$(server_accepts)"
printf '%s\n' "$failure_http" >"$RESULT_DIR/failure-http.log"
printf '%s\n' "$failure_protect" >"$RESULT_DIR/failure-protect.log"
printf '%s\n' "$failure_hev" >"$RESULT_DIR/failure-hev.log"
echo "failure_server_accept_before=$before_failure after=$after_failure"
grep -Fq 'protect fd=' <<<"$failure_protect"
grep -Fq 'result=0' <<<"$failure_protect"
grep -Fq 'socks5 client protect fd' <<<"$failure_hev"
grep -Fq ' fail elapsedMs=' <<<"$failure_http"
[[ "$before_failure" == "$after_failure" ]]

adb_cmd shell ps -A -n -Z -o LABEL,USER,PID,PPID,NAME,ARGS >"$RESULT_DIR/processes.txt"
adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' >"$RESULT_DIR/logcat.txt"
adb_cmd shell cat "$SERVER_LOG" >"$RESULT_DIR/final-socks-server.log"

echo "PASS: 3 IPv4 + 3 IPv6 protected upstream sockets; forced failure was explicit"
echo "result_dir=$RESULT_DIR"
