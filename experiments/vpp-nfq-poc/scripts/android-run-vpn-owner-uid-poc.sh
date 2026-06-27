#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify Android VpnService packet tuple -> getConnectionOwnerUid.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
TCP_HOST="${TCP_HOST:-142.251.13.94}"
TCP_PORT="${TCP_PORT:-80}"
UDP_HOST="${UDP_HOST:-8.8.8.8}"
UDP_PORT="${UDP_PORT:-53}"
START_WAIT="${START_WAIT:-3}"
PROBE_WAIT="${PROBE_WAIT:-7}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpn-owner-uid-poc.log"
APP_LOG_ROOT="/data/user/0/$PACKAGE/files/logs"
VPN_LOG="$APP_LOG_ROOT/vpn-fd-probe.log"
HTTP_LOG="$APP_LOG_ROOT/app-http-probe.log"
UDP_LOG="$APP_LOG_ROOT/app-udp-probe.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPN owner UID POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "tcp=$TCP_HOST:$TCP_PORT"
echo "udp=$UDP_HOST:$UDP_PORT"

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
echo "package_uid=$package_uid"

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "rm -f '$VPN_LOG' '$HTTP_LOG' '$UDP_LOG'"

echo
echo "## start native VPN probe"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez start true --es mode native
sleep "$START_WAIT"

echo
echo "## trigger TCP probe"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appHttpProbe true \
  --es host "$TCP_HOST" \
  --ei port "$TCP_PORT" \
  --es path "/owner-uid-poc"

echo
echo "## trigger UDP probe"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appUdpProbe true \
  --es host "$UDP_HOST" \
  --ei port "$UDP_PORT"

sleep "$PROBE_WAIT"

echo
echo "## vpn-fd-probe.log"
vpn_log="$(adb_su "cat '$VPN_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$vpn_log"

echo
echo "## app-http-probe.log"
adb_su "cat '$HTTP_LOG' 2>/dev/null || true" | tr -d '\r'

echo
echo "## app-udp-probe.log"
adb_su "cat '$UDP_LOG' 2>/dev/null || true" | tr -d '\r'

if ! grep -Eq "ipv4 proto=6 .*ownerUid=$package_uid" <<<"$vpn_log"; then
  echo "expected TCP ownerUid=$package_uid in VPN packet log" >&2
  exit 1
fi
if ! grep -Eq "ipv4 proto=17 .*ownerUid=$package_uid" <<<"$vpn_log"; then
  echo "expected UDP ownerUid=$package_uid in VPN packet log" >&2
  exit 1
fi

echo
echo "ok: VPN packet tuple owner UID lookup returned package uid for TCP and UDP"
