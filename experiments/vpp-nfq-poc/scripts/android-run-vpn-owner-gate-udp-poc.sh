#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify owner UID gate handles UDP packet decisions.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
IP_FAMILY="${IP_FAMILY:-inet4}"
HOST="${HOST:-}"
PORT="${PORT:-53}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
STOP_WAIT="${STOP_WAIT:-2}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpn-owner-gate-udp-$IP_FAMILY-poc.log"
UDP_LOG="/data/user/0/$PACKAGE/files/logs/app-udp-probe.log"
GATE_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-owner-gate.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"

case "$IP_FAMILY" in
  inet4)
    HOST="${HOST:-8.8.8.8}"
    ENABLE_IPV6=false
    EXPECT_LOG_FAMILY="10.111.0.2"
    ;;
  inet6)
    HOST="${HOST:-2606:4700:4700::1111}"
    ENABLE_IPV6=true
    EXPECT_LOG_FAMILY="fd00:111:111::2"
    ;;
  *)
    echo "unsupported IP_FAMILY=$IP_FAMILY; expected inet4 or inet6" >&2
    exit 1
    ;;
esac

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPN owner UDP gate POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "ip_family=$IP_FAMILY"
echo "udp=$HOST:$PORT"

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

run_case() {
  local name="$1"
  local block_uid="$2"
  local expect="$3"

  echo
  echo "## case $name block_uid=$block_uid expect=$expect"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
  adb_su "rm -f '$UDP_LOG' '$GATE_LOG' '$HEV_LOG'"

  start_args=(shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-gate \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$block_uid")
  if [[ "$ENABLE_IPV6" == "true" ]]; then
    start_args+=(--ez enableIpv6 true)
  fi
  adb_cmd "${start_args[@]}"
  sleep "$START_WAIT"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appUdpProbe true \
    --es host "$HOST" \
    --ei port "$PORT"
  sleep "$PROBE_WAIT"

  echo
  echo "### app-udp-probe.log"
  udp_log="$(adb_su "cat '$UDP_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$udp_log"

  echo
  echo "### owner gate log"
  gate_log="$(adb_su "cat '$GATE_LOG' 2>/dev/null || true" | tr -d '\r')"
  printf '%s\n' "$gate_log"

  echo
  echo "### hev log"
  adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r'

  echo
  echo "### stop"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true
  sleep "$STOP_WAIT"

  if ! grep -q 'ok bytes=' <<<"$udp_log"; then
    echo "case $name expected UDP probe send ok" >&2
    exit 1
  fi
  if [[ "$expect" == "allow" ]]; then
    if ! grep -Eq "gate forward .*proto=17 $EXPECT_LOG_FAMILY:.*ownerUid=$package_uid" <<<"$gate_log"; then
      echo "case $name expected UDP gate forward ownerUid=$package_uid" >&2
      exit 1
    fi
  else
    if ! grep -Eq "gate drop .*proto=17 $EXPECT_LOG_FAMILY:.*ownerUid=$package_uid" <<<"$gate_log"; then
      echo "case $name expected UDP gate drop ownerUid=$package_uid" >&2
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
echo "ok: VPN owner UDP gate forwards on miss and drops on package UID hit"
