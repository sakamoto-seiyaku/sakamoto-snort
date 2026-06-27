#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify Android VPP owner resolver handles UDP UID verdicts.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-8.8.8.8}"
PORT="${PORT:-53}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-package}"
REDIRECT_THREAD="${REDIRECT_THREAD:-}"
ENABLE_IPV6="${ENABLE_IPV6:-0}"
EXPECT_DROP="${EXPECT_DROP:-1}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
STOP_WAIT="${STOP_WAIT:-2}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-owner-resolver-udp-poc.log"
UDP_LOG="/data/user/0/$PACKAGE/files/logs/app-udp-probe.log"
VPP_CLI_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-cli.log"
RESOLVER_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-owner-resolver.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

exec > >(tee "$LOG") 2>&1

echo "# Android VPP owner UDP resolver POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "udp=$HOST:$PORT"
echo "block_owner_uid=$BLOCK_OWNER_UID"
echo "redirect_thread=$REDIRECT_THREAD"
echo "enable_ipv6=$ENABLE_IPV6"
echo "expect_drop=$EXPECT_DROP"

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
if [[ "$BLOCK_OWNER_UID" == "package" ]]; then
  BLOCK_OWNER_UID="$package_uid"
fi
echo "package_uid=$package_uid"
echo "effective_block_owner_uid=${BLOCK_OWNER_UID:-none}"

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "rm -f '$UDP_LOG' '$VPP_CLI_LOG' '$RESOLVER_LOG' '$HEV_LOG' /data/user/0/$PACKAGE/files/vpp/logs/vpp-shim.log"

echo
echo "## start vpp-hev-owner-resolver"
start_args=(shell am start -n "$PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$PACKAGE")
if [[ -n "$BLOCK_OWNER_UID" ]]; then
  start_args+=(--ei blockOwnerUid "$BLOCK_OWNER_UID")
fi
if [[ -n "$REDIRECT_THREAD" ]]; then
  start_args+=(--ei redirectThread "$REDIRECT_THREAD")
fi
if [[ "$ENABLE_IPV6" == "1" ]]; then
  start_args+=(--ez enableIpv6 true)
fi
adb_cmd "${start_args[@]}"
sleep "$START_WAIT"

echo
echo "## app UDP probe"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appUdpProbe true \
  --es host "$HOST" \
  --ei port "$PORT"
sleep "$PROBE_WAIT"

echo
echo "## app-udp-probe.log"
udp_log="$(adb_su "cat '$UDP_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$udp_log"

echo
echo "## vpp-cli.log"
vpp_cli="$(adb_su "cat '$VPP_CLI_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$vpp_cli"

echo
echo "## resolver log"
resolver_log="$(adb_su "cat '$RESOLVER_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$resolver_log"

echo
echo "## hev log"
adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r'

echo
echo "## stop"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true
sleep "$STOP_WAIT"

if ! grep -q 'ok bytes=' <<<"$udp_log"; then
  echo "expected UDP probe send ok" >&2
  exit 1
fi
if [[ "$ENABLE_IPV6" == "1" ]]; then
  if ! grep -Fq 'last-tuple ip6 proto 17' <<<"$vpp_cli" \
    || ! grep -Fq -- "-> [$HOST]:$PORT" <<<"$vpp_cli"; then
    echo "expected VPP IPv6 UDP last tuple to $HOST:$PORT" >&2
    exit 1
  fi
else
  if ! grep -Eq 'last-tuple ip4 proto 17 .* -> '"$HOST:$PORT" <<<"$vpp_cli"; then
    echo "expected VPP last tuple to be UDP $HOST:$PORT" >&2
    exit 1
  fi
fi
if ! grep -Eq 'resolver enabled 1 fd 5 queries [1-9].* hits [1-9].* errors 0' <<<"$vpp_cli"; then
  echo "expected VPP resolver UDP hits without errors" >&2
  exit 1
fi
if ! grep -Eq "resolver query=.* proto=17 .* -> $HOST:$PORT uid=$package_uid" <<<"$resolver_log"; then
  echo "expected native resolver UDP log with uid=$package_uid" >&2
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
if [[ "$EXPECT_DROP" == "1" ]]; then
  if ! grep -Eq 'uid-block enabled 1 uid '"$package_uid"' packets [1-9]' <<<"$vpp_cli"; then
    echo "expected VPP UDP uid-block counter for package uid $package_uid" >&2
    exit 1
  fi
else
  if grep -Eq 'uid-block enabled 1 uid '"$package_uid"' packets [1-9]' <<<"$vpp_cli"; then
    echo "unexpected UDP uid-block packets in allow case" >&2
    exit 1
  fi
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
echo "ok: Android VPP owner resolver handled UDP UID verdict"
