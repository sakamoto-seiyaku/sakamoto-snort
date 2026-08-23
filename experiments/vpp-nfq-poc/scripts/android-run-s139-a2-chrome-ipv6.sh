#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: narrow ordinary-App IPv6 TCP/UDP observation cell.
# This runner only proves the UID/policy boundary; it does not claim egress.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE="${APP_PACKAGE:-com.android.chrome}"
TARGET_URL="${TARGET_URL:-https://[2606:4700:4700::1111]/}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-chrome-ipv6}"
START_WAIT="${START_WAIT:-7}"
PROBE_WAIT="${PROBE_WAIT:-8}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-99999}"

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
  adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2 Chrome IPv6 narrow cell"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE app_package=$APP_PACKAGE target=$TARGET_URL"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$HEV_PATH' '$SHIM_PATH'"

echo "## start IPv6 owner resolver"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$APP_PACKAGE" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --ez ownerCache true \
  --ez enableIpv6 true
sleep "$START_WAIT"

echo "## trigger Chrome URL"
adb_cmd shell am start -a android.intent.action.VIEW -p "$APP_PACKAGE" -d "$TARGET_URL"
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
echo "## proc tcp6"
adb_su "cat /proc/net/tcp6 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/proc-net-tcp6.txt"

echo "## cleanup"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
sleep 2
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -n "$leftovers" ]]; then
  echo "leftover-vpp=$leftovers"
  exit 1
fi
echo "RESULT narrow-observation-only"
