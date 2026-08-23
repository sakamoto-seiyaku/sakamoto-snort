#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: two ordinary Android app UIDs share one VPN allow-list.
# This is a UID/policy boundary cell only; it makes no external-forwarding
# claim. Chrome is driven by a URL and Maps by a geo intent so both packages
# have an opportunity to create real device sockets through the VPN.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_ONE="${APP_ONE:-com.android.chrome}"
APP_TWO="${APP_TWO:-com.google.android.apps.maps}"
CHROME_URL="${CHROME_URL:-http://1.1.1.1:80/}"
MAPS_URI="${MAPS_URI:-geo:25.0330,121.5654?q=25.0330,121.5654}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-two-ordinary-apps}"
START_WAIT="${START_WAIT:-7}"
PROBE_WAIT="${PROBE_WAIT:-8}"
CONCURRENT="${CONCURRENT:-0}"

VPP_CLI_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-cli.log"
RESOLVER_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-owner-resolver.log"
HEV_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-hev.log"
SHIM_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-shim.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

cleanup() {
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$APP_ONE" >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$APP_TWO" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2 two ordinary app UID cell"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE app_one=$APP_ONE app_two=$APP_TWO"
echo "chrome_url=$CHROME_URL maps_uri=$MAPS_URI concurrent=$CONCURRENT"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_ONE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_TWO" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$HEV_PATH' '$SHIM_PATH'"

echo "## package UIDs"
adb_cmd shell cmd package list packages -U \
  | tr -d '\r' \
  | grep -E "package:($APP_ONE|$APP_TWO) uid:" \
  | tee "$RESULT_DIR/package-uids.txt"

echo "## start owner resolver with both ordinary apps allowed"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$APP_ONE,$APP_TWO" \
  --ei blockOwnerUid 99999 \
  --ez ownerCache true \
  --ez enableIpv6 true
sleep "$START_WAIT"

echo "## trigger Chrome and Maps"
adb_cmd shell am start -a android.intent.action.VIEW -p "$APP_ONE" -d "$CHROME_URL"
if [[ "$CONCURRENT" != "1" ]]; then
  sleep 2
fi
adb_cmd shell am start -a android.intent.action.VIEW -p "$APP_TWO" -d "$MAPS_URI"
sleep "$PROBE_WAIT"

capture() {
  local name="$1" path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/$name"
}

echo "## connectivity"
adb_cmd shell dumpsys connectivity | tr -d '\r' | tee "$RESULT_DIR/dumpsys-connectivity.txt"
echo "## vpp cli"
capture vpp-cli.log "$VPP_CLI_PATH"
echo "## resolver"
capture vpp-owner-resolver.log "$RESOLVER_PATH"
echo "## hev/shim"
capture vpp-hev.log "$HEV_PATH"
capture vpp-shim.log "$SHIM_PATH"
echo "## proc sockets"
adb_su "cat /proc/net/tcp 2>/dev/null || true; cat /proc/net/tcp6 2>/dev/null || true" \
  | tr -d '\r' | tee "$RESULT_DIR/proc-net-tcp-all.txt"

echo "## cleanup"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
sleep 2
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -n "$leftovers" ]]; then
  echo "leftover-vpp=$leftovers"
  exit 1
fi
echo "RESULT narrow-observation-only"
