#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: prove the Android VPN/VPP/HEV path runs as an app UID without su.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-no-su}"
HOST4="${HOST4:-142.251.13.94}"
HOST6="${HOST6:-2606:4700:4700::1111}"
HTTP_PORT="${HTTP_PORT:-80}"
UDP4_HOST="${UDP4_HOST:-8.8.8.8}"
UDP6_HOST="${UDP6_HOST:-2606:4700:4700::1111}"
UDP_PORT="${UDP_PORT:-53}"
START_WAIT="${START_WAIT:-6}"
HTTP_WAIT="${HTTP_WAIT:-7}"
UDP_WAIT="${UDP_WAIT:-5}"
STOP_WAIT="${STOP_WAIT:-2}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-2-app-uid-no-su-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"

APP_HTTP_LOG="files/logs/app-http-probe.log"
APP_UDP_LOG="files/logs/app-udp-probe.log"
VPP_CLI_LOG="files/vpp/logs/vpp-cli.log"
VPP_STDOUT_LOG="files/vpp/logs/vpp-stdout.log"
RESOLVER_LOG="files/vpp/logs/vpp-owner-resolver.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
SHIM_LOG="files/vpp/logs/vpp-shim.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null || true
}

clear_app_logs() {
  app_cmd rm -f \
    "$APP_HTTP_LOG" \
    "$APP_UDP_LOG" \
    "$VPP_CLI_LOG" \
    "$VPP_STDOUT_LOG" \
    "$RESOLVER_LOG" \
    "$HEV_LOG" \
    "$SHIM_LOG" >/dev/null
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
  stop_app
  stop_server
}
trap cleanup EXIT

server_count() {
  local host="$1"
  local port="$2"
  local count
  count="$(adb_cmd shell "grep -Fc 'connect $host:$port' '$SERVER_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1)"
  printf '%s\n' "${count:-0}"
}

capture_processes() {
  local case_name="$1"
  local snapshot
  snapshot="$(adb_cmd shell ps -A -n -Z -o LABEL,USER,PID,PPID,NAME,ARGS | tr -d '\r')"
  printf '%s\n' "$snapshot" >"$RESULT_DIR/$case_name-processes-all.txt"
  printf '%s\n' "$snapshot" | awk -v package="$PACKAGE" '
    index($0, package) > 0 || $0 ~ /libvpppoc/ || $0 ~ /(^|[[:space:]])vpp([[:space:]]|$)/ {
      print
    }
  ' | tee "$RESULT_DIR/$case_name-processes-relevant.txt"
}

persist_case_logs() {
  local case_name="$1"
  local probe_log="$2"
  local vpp_cli="$3"
  local resolver_log="$4"
  local hev_log="$5"
  printf '%s\n' "$probe_log" >"$RESULT_DIR/$case_name-probe.log"
  printf '%s\n' "$vpp_cli" >"$RESULT_DIR/$case_name-vpp-cli.log"
  printf '%s\n' "$resolver_log" >"$RESULT_DIR/$case_name-resolver.log"
  printf '%s\n' "$hev_log" >"$RESULT_DIR/$case_name-hev.log"
}

assert_common() {
  local family="$1"
  local protocol="$2"
  local host="$3"
  local port="$4"
  local vpp_cli="$5"
  local resolver_log="$6"

  grep -Fq "last-tuple $family proto $protocol" <<<"$vpp_cli" || {
    echo "expected $family protocol $protocol tuple" >&2
    return 1
  }
  grep -Fq "$host" <<<"$vpp_cli" || {
    echo "expected destination host $host in VPP tuple" >&2
    return 1
  }
  grep -Fq ":$port" <<<"$vpp_cli" || {
    echo "expected destination port $port in VPP tuple" >&2
    return 1
  }
  grep -Eq 'resolver enabled 1 fd 5 queries [1-9].* hits [1-9].* errors 0' <<<"$vpp_cli" || {
    echo "expected VPP resolver hits without errors" >&2
    return 1
  }
  grep -Eq "resolver query=.* uid=$package_uid" <<<"$resolver_log" || {
    echo "expected Android resolver to return package uid $package_uid" >&2
    return 1
  }
}

assert_uid_verdict() {
  local expect="$1"
  local block_uid="$2"
  local vpp_cli="$3"

  if [[ "$expect" == "drop" ]]; then
    grep -Eq "uid-block enabled 1 uid $package_uid packets [1-9]" <<<"$vpp_cli" || {
      echo "expected VPP to drop packets for package uid $package_uid" >&2
      return 1
    }
  else
    if grep -Eq "uid-block enabled 1 uid $block_uid packets [1-9]" <<<"$vpp_cli"; then
      echo "unexpected UID block packets for miss uid $block_uid" >&2
      return 1
    fi
  fi
}

run_http_case() {
  local case_name="$1"
  local family="$2"
  local host="$3"
  local enable_ipv6="$4"
  local block_uid="$5"
  local expect="$6"
  local before_count
  local after_count
  local app_log
  local vpp_cli
  local resolver_log
  local hev_log

  echo
  echo "## HTTP case $case_name family=$family expect=$expect block_uid=$block_uid"
  stop_app
  clear_app_logs
  before_count="$(server_count "$host" "$HTTP_PORT")"

  start_args=(shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-resolver \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$block_uid")
  if [[ "$enable_ipv6" == "1" ]]; then
    start_args+=(--ez enableIpv6 true)
  fi
  adb_cmd "${start_args[@]}"
  sleep "$START_WAIT"
  capture_processes "$case_name"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true \
    --es host "$host" \
    --ei port "$HTTP_PORT" \
    --es path "/sakamoto-2-$case_name"
  sleep "$HTTP_WAIT"

  app_log="$(app_read "$APP_HTTP_LOG" | tr -d '\r')"
  vpp_cli="$(app_read "$VPP_CLI_LOG" | tr -d '\r')"
  resolver_log="$(app_read "$RESOLVER_LOG" | tr -d '\r')"
  hev_log="$(app_read "$HEV_LOG" | tr -d '\r')"
  after_count="$(server_count "$host" "$HTTP_PORT")"
  persist_case_logs "$case_name" "$app_log" "$vpp_cli" "$resolver_log" "$hev_log"

  printf '%s\n' "$app_log"
  printf '%s\n' "$vpp_cli"
  printf '%s\n' "$resolver_log"
  echo "socks_count_before=$before_count socks_count_after=$after_count"

  assert_common "$family" 6 "$host" "$HTTP_PORT" "$vpp_cli" "$resolver_log"
  assert_uid_verdict "$expect" "$block_uid" "$vpp_cli"
  if [[ "$expect" == "allow" ]]; then
    grep -Fq 'HTTP/1.0 200 OK' <<<"$app_log" || {
      echo "expected HTTP allow response" >&2
      return 1
    }
    (( after_count > before_count )) || {
      echo "expected SOCKS connection count to increase" >&2
      return 1
    }
  else
    if grep -Fq 'HTTP/1.0 200 OK' <<<"$app_log"; then
      echo "expected HTTP request to be blocked" >&2
      return 1
    fi
    (( after_count == before_count )) || {
      echo "expected blocked flow not to reach SOCKS server" >&2
      return 1
    }
  fi

  stop_app
  sleep "$STOP_WAIT"
  echo "ok: $case_name"
}

run_udp_case() {
  local case_name="$1"
  local family="$2"
  local host="$3"
  local enable_ipv6="$4"
  local block_uid="$5"
  local expect="$6"
  local udp_log
  local vpp_cli
  local resolver_log
  local hev_log

  echo
  echo "## UDP case $case_name family=$family expect=$expect block_uid=$block_uid"
  stop_app
  clear_app_logs

  start_args=(shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-resolver \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$block_uid")
  if [[ "$enable_ipv6" == "1" ]]; then
    start_args+=(--ez enableIpv6 true)
  fi
  adb_cmd "${start_args[@]}"
  sleep "$START_WAIT"
  capture_processes "$case_name"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appUdpProbe true \
    --es host "$host" \
    --ei port "$UDP_PORT" \
    --ei count 1
  sleep "$UDP_WAIT"

  udp_log="$(app_read "$APP_UDP_LOG" | tr -d '\r')"
  vpp_cli="$(app_read "$VPP_CLI_LOG" | tr -d '\r')"
  resolver_log="$(app_read "$RESOLVER_LOG" | tr -d '\r')"
  hev_log="$(app_read "$HEV_LOG" | tr -d '\r')"
  persist_case_logs "$case_name" "$udp_log" "$vpp_cli" "$resolver_log" "$hev_log"

  printf '%s\n' "$udp_log"
  printf '%s\n' "$vpp_cli"
  printf '%s\n' "$resolver_log"

  grep -Fq 'ok bytes=' <<<"$udp_log" || {
    echo "expected UDP send API success" >&2
    return 1
  }
  assert_common "$family" 17 "$host" "$UDP_PORT" "$vpp_cli" "$resolver_log"
  assert_uid_verdict "$expect" "$block_uid" "$vpp_cli"

  stop_app
  sleep "$STOP_WAIT"
  echo "ok: $case_name"
}

echo "# SAKAMOTO-2 ordinary app UID / no-su VPN matrix"
echo "run_id=$RUN_ID"
echo "result_dir=$RESULT_DIR"
echo "adb_serial=$(adb_target_desc)"
echo "adb_identity=$(adb_cmd shell id | tr -d '\r')"
echo "device_model=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
echo "android_release=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
echo "android_api=$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
echo "device_abi=$(adb_cmd shell getprop ro.product.cpu.abi | tr -d '\r')"
echo "bootloader_locked=$(adb_cmd shell getprop ro.boot.flash.locked | tr -d '\r')"
echo "verified_boot_state=$(adb_cmd shell getprop ro.boot.verifiedbootstate | tr -d '\r')"

if [[ "$BUILD_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
package_uid="$(awk -F'uid:' -v package="package:$PACKAGE" '
  index($0, package) == 1 { print $2; exit }
' <<<"$packages")"
[[ -n "$package_uid" ]] || {
  echo "failed to resolve package uid for $PACKAGE" >&2
  exit 1
}
miss_uid=$((package_uid + 100000))
echo "package_uid=$package_uid"
echo "miss_uid=$miss_uid"
echo "run_as_identity=$(app_cmd id | tr -d '\r')"
sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk"
sha256sum "$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage/bin/vpp"

"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
stop_app
stop_server
adb_cmd shell mkdir -p "$REMOTE_ROOT"
adb_cmd shell rm -f "$SERVER_LOG"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_cmd shell chmod 755 "$REMOTE_SERVER"
adb_cmd shell "nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! >'$SERVER_PID'"
sleep 1
echo "socks_server_identity=$(adb_cmd shell ps -A -n -Z -o LABEL,USER,PID,PPID,NAME,ARGS | tr -d '\r' | awk '/android-socks5-smoke-server/ { print; exit }')"

run_http_case ip4-tcp-allow ip4 "$HOST4" 0 "$miss_uid" allow
run_http_case ip4-tcp-drop ip4 "$HOST4" 0 "$package_uid" drop
run_http_case ip6-tcp-allow ip6 "$HOST6" 1 "$miss_uid" allow
run_http_case ip6-tcp-drop ip6 "$HOST6" 1 "$package_uid" drop
run_udp_case ip4-udp-allow ip4 "$UDP4_HOST" 0 "$miss_uid" allow
run_udp_case ip4-udp-drop ip4 "$UDP4_HOST" 0 "$package_uid" drop
run_udp_case ip6-udp-allow ip6 "$UDP6_HOST" 1 "$miss_uid" allow
run_udp_case ip6-udp-drop ip6 "$UDP6_HOST" 1 "$package_uid" drop

echo
echo "PASS: SAKAMOTO-2 app UID/no-su IPv4+IPv6 TCP+UDP allow/drop matrix"
