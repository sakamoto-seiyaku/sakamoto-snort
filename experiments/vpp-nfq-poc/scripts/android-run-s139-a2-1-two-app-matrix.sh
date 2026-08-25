#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2-1: deterministic two-App dual-stack UID matrix.
#
# This runner only orchestrates the device and retains raw evidence.  The
# verifier owns all acceptance rules.  The two traffic APKs share one Java
# implementation but have distinct package IDs/process UIDs.  Each tuple has
# a unique source port, and each operation is repeated twice so an asynchronous
# owner lookup can complete without changing the canonical tuple.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VERIFIER="$SCRIPT_DIR/verify-s139-a2.py"

LOCAL_VPN_APK="${LOCAL_VPN_APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
LOCAL_APP_A_APK="${LOCAL_APP_A_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
LOCAL_APP_B_APK="${LOCAL_APP_B_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appb-debug.apk}"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE_A="${APP_PACKAGE_A:-com.sakamoto.snort.poc.appa}"
APP_PACKAGE_B="${APP_PACKAGE_B:-com.sakamoto.snort.poc.appb}"
TRAFFIC_ACTIVITY="${TRAFFIC_ACTIVITY:-com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
MODE="${MODE:-vpp-hev-owner-resolver}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-99999}"
START_WAIT="${START_WAIT:-6}"
TUPLE_WAIT="${TUPLE_WAIT:-4}"
RESOLVER_WAIT="${RESOLVER_WAIT:-5}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-1-two-app-matrix}"
FIXTURE_SCRIPT="${FIXTURE_SCRIPT:-$SCRIPT_DIR/s152-a2-1-fixture.py}"
FIXTURE_LOG="${FIXTURE_LOG:-$RESULT_DIR/s152-a2-1-fixture.jsonl}"
FIXTURE_STDOUT="${FIXTURE_STDOUT:-$RESULT_DIR/s152-a2-1-fixture.stdout.log}"
FIXTURE_HOST4="${FIXTURE_HOST4:-${FIXTURE_HOST:-}}"
FIXTURE_HOST6="${FIXTURE_HOST6:-}"
FIXTURE_BIND_HOST4="${FIXTURE_BIND_HOST4:-}"
FIXTURE_BIND_HOST6="${FIXTURE_BIND_HOST6:-}"
FIXTURE_TCP_PORT="${FIXTURE_TCP_PORT:-55443}"
FIXTURE_UDP_PORT="${FIXTURE_UDP_PORT:-55553}"
FIXTURE_READY_WAIT="${FIXTURE_READY_WAIT:-20}"
UID_CONTRACT_CELL="A2-1"

VPP_ROOT="/data/user/0/$VPN_PACKAGE/files/vpp"
VPP_CLI_PATH="$VPP_ROOT/logs/vpp-cli.log"
RESOLVER_PATH="$VPP_ROOT/logs/vpp-owner-resolver.log"
SHIM_PATH="$VPP_ROOT/logs/vpp-shim.log"
HEV_PATH="$VPP_ROOT/logs/vpp-hev.log"
PROTECT_PATH="$VPP_ROOT/logs/vpp-protect.log"
RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance.json"
FAILURE_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance-failure.json"
VPP_START_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpp-start-provenance.json"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
RUNTIME_A_PATH="/data/user/0/$APP_PACKAGE_A/files/debug/a2-1-runtime.jsonl"
RUNTIME_B_PATH="/data/user/0/$APP_PACKAGE_B/files/debug/a2-1-runtime.jsonl"

mkdir -p "$RESULT_DIR"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

fixture_pid=""

discover_fixture_host4() {
  if [[ -n "$FIXTURE_HOST4" ]]; then
    printf '%s\n' "$FIXTURE_HOST4"
    return 0
  fi
  ip -4 route get 192.0.2.1 2>/dev/null \
    | sed -n 's/.* src \([0-9.][0-9.]*\).*/\1/p' | head -n 1
}

discover_fixture_host6() {
  if [[ -n "$FIXTURE_HOST6" ]]; then
    printf '%s\n' "$FIXTURE_HOST6"
    return 0
  fi
  ip -6 route get 2001:db8::1 2>/dev/null \
    | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1
}

start_fixture() {
  FIXTURE_HOST4="$(discover_fixture_host4)"
  FIXTURE_HOST6="$(discover_fixture_host6)"
  [[ -n "$FIXTURE_HOST4" && -n "$FIXTURE_HOST6" ]] || {
    echo "controlled A2-1 fixture requires both IPv4 and IPv6 host addresses" >&2
    return 2
  }
  FIXTURE_BIND_HOST4="${FIXTURE_BIND_HOST4:-$FIXTURE_HOST4}"
  FIXTURE_BIND_HOST6="${FIXTURE_BIND_HOST6:-$FIXTURE_HOST6}"
  case "$FIXTURE_HOST4,$FIXTURE_HOST6" in
    *1.1.1.1*|*2606:4700:4700::*)
      echo "public resolver addresses are forbidden as the A2-1 fixture oracle" >&2
      return 2
      ;;
  esac
  [[ "$FIXTURE_TCP_PORT" =~ ^[1-9][0-9]{2,4}$ ]] || {
    echo "FIXTURE_TCP_PORT must be a valid non-privileged port" >&2
    return 2
  }
  [[ "$FIXTURE_UDP_PORT" =~ ^[1-9][0-9]{2,4}$ ]] || {
    echo "FIXTURE_UDP_PORT must be a valid non-privileged port" >&2
    return 2
  }
  [[ -f "$FIXTURE_SCRIPT" ]] || {
    echo "missing controlled A2-1 fixture script: $FIXTURE_SCRIPT" >&2
    return 2
  }
  : >"$FIXTURE_LOG"
  python3 "$FIXTURE_SCRIPT" \
    --bind4 "$FIXTURE_BIND_HOST4" --bind6 "$FIXTURE_BIND_HOST6" \
    --tcp-port "$FIXTURE_TCP_PORT" --udp-port "$FIXTURE_UDP_PORT" \
    --log "$FIXTURE_LOG" >"$FIXTURE_STDOUT" 2>&1 &
  fixture_pid=$!
  local ready=0
  for _ in $(seq 1 "$FIXTURE_READY_WAIT"); do
    if ! kill -0 "$fixture_pid" 2>/dev/null; then
      echo "controlled A2-1 fixture exited before readiness" >&2
      return 1
    fi
    ready="$(grep -c '"event": "ready"' "$FIXTURE_LOG" 2>/dev/null || true)"
    if [[ "$ready" == 4 ]] && grep -q '"event": "fixture_ready"' "$FIXTURE_LOG"; then
      printf '%s\n' \
        "schema=s152-a2-1-fixture-readiness/v1" \
        "publicInternetClaim=false" \
        "fixtureHost4=$FIXTURE_HOST4" \
        "fixtureHost6=$FIXTURE_HOST6" \
        "fixtureBindHost4=$FIXTURE_BIND_HOST4" \
        "fixtureBindHost6=$FIXTURE_BIND_HOST6" \
        "tcpPort=$FIXTURE_TCP_PORT" \
        "udpPort=$FIXTURE_UDP_PORT" \
        "readyEvents=$ready" >"$RESULT_DIR/fixture-readiness.properties"
      return 0
    fi
    sleep 0.25
  done
  echo "controlled A2-1 fixture did not publish four ready events" >&2
  return 1
}

capture_remote() {
  local name="$1"
  local path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$RESULT_DIR/$name"
}

capture_apk_provenance() {
  : >"$RESULT_DIR/apk-provenance.tsv"
  local package_name path line digest
  for package_name in "$VPN_PACKAGE" "$APP_PACKAGE_A" "$APP_PACKAGE_B"; do
    while IFS= read -r line; do
      path="${line#package:}"
      [[ "$path" == /* ]] || continue
      digest="$(adb_su "sha256sum '$path' 2>/dev/null || true" \
        | tr -d '\r' | awk 'NF { print $1; exit }')"
      printf '%s\t%s\t%s\n' "$package_name" "$path" "$digest" \
        >>"$RESULT_DIR/apk-provenance.tsv"
    done < <(adb_cmd shell pm path "$package_name" 2>/dev/null | tr -d '\r')
  done
}

cleanup_done=0
cleanup() {
  if (( cleanup_done == 1 )); then
    return 0
  fi
  cleanup_done=1
  set +e
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1
  sleep 1
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1
  adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1
  adb_cmd shell am force-stop "$APP_PACKAGE_B" >/dev/null 2>&1
  {
    echo "processes:"
    adb_su "ps -A 2>/dev/null | grep '[v]pp\|[s]nort-vpn' || true" \
      | tr -d '\r'
    echo "tun0:"
    adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r'
    echo "vpn:"
    adb_cmd shell dumpsys connectivity 2>/dev/null | tr -d '\r' \
      | grep -E "Vpn|tun0|$VPN_PACKAGE" || true
  } >"$RESULT_DIR/cleanup.txt"
  if [[ -n "$fixture_pid" ]]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
    wait "$fixture_pid" >/dev/null 2>&1 || true
  fi
  set -e
}
trap cleanup EXIT

start_fixture

echo "# SAKAMOTO-139 A2-1 two-App dual-stack matrix"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE"
echo "app_a=$APP_PACKAGE_A app_b=$APP_PACKAGE_B"
echo "activity=$TRAFFIC_ACTIVITY"
echo "mode=$MODE block_owner_uid=$BLOCK_OWNER_UID"
echo "fixture_host4=$FIXTURE_HOST4 fixture_host6=$FIXTURE_HOST6"
echo "fixture_tcp_port=$FIXTURE_TCP_PORT fixture_udp_port=$FIXTURE_UDP_PORT"
echo "public-internet=NON-CLAIM; external-connect/reply=NON-CLAIM; logcat=DIAGNOSTIC-ONLY"

for apk in "$LOCAL_VPN_APK" "$LOCAL_APP_A_APK" "$LOCAL_APP_B_APK"; do
  [[ -f "$apk" ]] || {
    echo "missing local APK: $apk" >&2
    exit 2
  }
done

local_vpn_apk_sha256="$(sha256sum "$LOCAL_VPN_APK" | awk '{print $1}')"
local_app_a_apk_sha256="$(sha256sum "$LOCAL_APP_A_APK" | awk '{print $1}')"
local_app_b_apk_sha256="$(sha256sum "$LOCAL_APP_B_APK" | awk '{print $1}')"
fixture_script_sha256="$(sha256sum "$FIXTURE_SCRIPT" | awk '{print $1}')"
expected_tun_plugin_sha256="$(unzip -p "$LOCAL_VPN_APK" \
  assets/vpp-tun-poc-plugin.sha256 2>/dev/null | tr -d '\r\n')"
[[ "$expected_tun_plugin_sha256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "local VpnLite APK lacks valid tun plugin provenance" >&2
  exit 2
}

for app_apk in "$LOCAL_APP_A_APK" "$LOCAL_APP_B_APK"; do
  adapter_properties="$(unzip -p "$app_apk" \
    assets/a2-1-traffic-adapter.properties 2>/dev/null || true)"
  grep -q '^schema=s139-a2-1-traffic-adapter-build/v1$' \
    <<<"$adapter_properties" || {
    echo "traffic APK lacks A2-1 build provenance: $app_apk" >&2
    exit 2
  }
done

echo "## install deterministic App APKs through repo device helper"
install_ok=true
adb_cmd install -r "$LOCAL_APP_A_APK" >/dev/null || install_ok=false
adb_cmd install -r "$LOCAL_APP_B_APK" >/dev/null || install_ok=false

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-packages-U.txt"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
app_a_uid="$(awk -F'uid:' -v pkg="package:$APP_PACKAGE_A" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
app_b_uid="$(awk -F'uid:' -v pkg="package:$APP_PACKAGE_B" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
vpn_uid="${vpn_uid//[[:space:]]/}"
app_a_uid="${app_a_uid//[[:space:]]/}"
app_b_uid="${app_b_uid//[[:space:]]/}"
[[ "$vpn_uid" =~ ^[0-9]+$ ]] || vpn_uid=-1
[[ "$app_a_uid" =~ ^[0-9]+$ ]] || app_a_uid=-1
[[ "$app_b_uid" =~ ^[0-9]+$ ]] || app_b_uid=-1
echo "vpn_uid=$vpn_uid app_a_uid=$app_a_uid app_b_uid=$app_b_uid"
echo "install_ok=$install_ok"

{
  echo "serial=$(adb_target_desc)"
  echo "model=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
  echo "fingerprint=$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
  echo "androidRelease=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
  echo "sdk=$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
} >"$RESULT_DIR/device-build.properties"
source_git_head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
source_git_dirty=false
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  source_git_dirty=true
fi
device_epoch="$(adb_cmd shell date +%s 2>/dev/null | tr -d '\r\n')"
[[ "$device_epoch" =~ ^[0-9]+$ ]] || device_epoch=-1
{
  echo "captureUtc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "captureEpoch=$(date -u +%s)"
  echo "deviceEpoch=$device_epoch"
  echo "gitHead=$source_git_head"
  echo "gitDirty=$source_git_dirty"
  echo "vpnApkSha256=$local_vpn_apk_sha256"
  echo "appAApkSha256=$local_app_a_apk_sha256"
  echo "appBApkSha256=$local_app_b_apk_sha256"
  echo "tunPocPluginSha256=$expected_tun_plugin_sha256"
  echo "fixtureScriptSha256=$fixture_script_sha256"
  echo "fixtureHost4=$FIXTURE_HOST4"
  echo "fixtureHost6=$FIXTURE_HOST6"
  echo "fixtureTcpPort=$FIXTURE_TCP_PORT"
  echo "fixtureUdpPort=$FIXTURE_UDP_PORT"
  echo "runner=$SCRIPT_DIR/$(basename "$0")"
} >"$RESULT_DIR/source-provenance.properties"
capture_apk_provenance

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_B" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$SHIM_PATH' '$HEV_PATH' \
  '$PROTECT_PATH' '$RECEIPT_PATH' '$FAILURE_RECEIPT_PATH' \
  '$VPP_START_RECEIPT_PATH' '$CONTRACT_PATH' '$RUNTIME_A_PATH' '$RUNTIME_B_PATH'"

echo "## start owner resolver with both deterministic packages and IPv6"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode "$MODE" \
  --es allowedPackage "$APP_PACKAGE_A,$APP_PACKAGE_B" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --es uidContractStage "A2-1-session" \
  --ez ownerCache true \
  --ez enableIpv6 true
sleep "$START_WAIT"

arm_uid_stage() {
  local stage_id="$1"
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" \
    --es uidContractStage "$stage_id" >/dev/null
  for _ in $(seq 1 20); do
    if adb_su "cat '$CONTRACT_PATH' 2>/dev/null || true" | tr -d '\r' \
      | grep -q '"outcome":"STAGE_BEGIN"' \
      && adb_su "cat '$CONTRACT_PATH' 2>/dev/null || true" | tr -d '\r' \
      | grep -q "\"cell_id\":\"$UID_CONTRACT_CELL\".*\"stage_id\":\"$stage_id\""; then
      return 0
    fi
    sleep 0.2
  done
  echo "UID contract stage did not arm: cell=$UID_CONTRACT_CELL stage=$stage_id" >&2
  return 1
}

emit_tuple() {
  local package_name="$1"
  local family="$2"
  local protocol="$3"
  local source_port="$4"
  local destination_host="$5"
  local destination_port="$6"
  local stage_id="$7"
  local activity="$package_name/$TRAFFIC_ACTIVITY"
  echo "## emit package=$package_name stage=$stage_id $family/$protocol $source_port -> $destination_host:$destination_port"
  arm_uid_stage "$stage_id"
  adb_cmd shell am start -a com.sakamoto.snort.a2traffic.EMIT \
    -n "$activity" \
    --es a2MatrixStageId "$stage_id" \
    --es a2MatrixFamily "$family" \
    --es a2MatrixProtocol "$protocol" \
    --ei a2MatrixSourcePort "$source_port" \
    --es a2MatrixDestinationHost "$destination_host" \
    --ei a2MatrixDestinationPort "$destination_port" \
    --ei a2MatrixTimeoutMillis 1200 \
    --ei a2MatrixRepeat 2
  sleep "$TUPLE_WAIT"
}

# The source ports are unique across both Apps and all four family/protocol
# combinations.  Tuple order is deterministic and strictly serial.
emit_tuple "$APP_PACKAGE_A" ip4 tcp 45641 "$FIXTURE_HOST4" "$FIXTURE_TCP_PORT" A2-1-appa-ip4-tcp
emit_tuple "$APP_PACKAGE_A" ip4 udp 45642 "$FIXTURE_HOST4" "$FIXTURE_UDP_PORT" A2-1-appa-ip4-udp
emit_tuple "$APP_PACKAGE_A" ip6 tcp 45643 "$FIXTURE_HOST6" "$FIXTURE_TCP_PORT" A2-1-appa-ip6-tcp
emit_tuple "$APP_PACKAGE_A" ip6 udp 45644 "$FIXTURE_HOST6" "$FIXTURE_UDP_PORT" A2-1-appa-ip6-udp
emit_tuple "$APP_PACKAGE_B" ip4 tcp 45651 "$FIXTURE_HOST4" "$FIXTURE_TCP_PORT" A2-1-appb-ip4-tcp
emit_tuple "$APP_PACKAGE_B" ip4 udp 45652 "$FIXTURE_HOST4" "$FIXTURE_UDP_PORT" A2-1-appb-ip4-udp
emit_tuple "$APP_PACKAGE_B" ip6 tcp 45653 "$FIXTURE_HOST6" "$FIXTURE_TCP_PORT" A2-1-appb-ip6-tcp
emit_tuple "$APP_PACKAGE_B" ip6 udp 45654 "$FIXTURE_HOST6" "$FIXTURE_UDP_PORT" A2-1-appb-ip6-udp
sleep "$RESOLVER_WAIT"

echo "## capture durable A2-1 evidence before cleanup"
capture_remote "vpn-session-provenance.json" "$RECEIPT_PATH"
capture_remote "vpn-session-provenance-failure.json" "$FAILURE_RECEIPT_PATH"
capture_remote "vpp-start-provenance.json" "$VPP_START_RECEIPT_PATH"
capture_remote "uid-attribution-contract.jsonl" "$CONTRACT_PATH"
capture_remote "a2-1-runtime-appa.jsonl" "$RUNTIME_A_PATH"
capture_remote "a2-1-runtime-appb.jsonl" "$RUNTIME_B_PATH"
capture_remote "vpp-cli.log" "$VPP_CLI_PATH"
capture_remote "vpp-owner-resolver.log" "$RESOLVER_PATH"
capture_remote "vpp-shim.log" "$SHIM_PATH"
capture_remote "vpp-hev.log" "$HEV_PATH"
capture_remote "vpp-protect.log" "$PROTECT_PATH"
adb_cmd shell dumpsys connectivity 2>/dev/null | tr -d '\r' \
  >"$RESULT_DIR/connectivity.txt" || true

grep -E 'last-tuple|resolver query=' \
  "$RESULT_DIR/vpp-cli.log" "$RESULT_DIR/vpp-owner-resolver.log" \
  >"$RESULT_DIR/exact-vpp-tuples.txt" || true

echo "## logcat diagnostic capture (not a verifier gate)"
adb_cmd shell logcat -d -t 800 -s SnortVpnLite:I SnortVpnService:I '*:S' \
  2>/dev/null | tr -d '\r' >"$RESULT_DIR/logcat-diagnostic.log" || true

python3 - "$RESULT_DIR/manifest.json" \
  "$VPN_PACKAGE" "$APP_PACKAGE_A" "$APP_PACKAGE_B" \
  "$vpn_uid" "$app_a_uid" "$app_b_uid" \
  "$local_vpn_apk_sha256" "$local_app_a_apk_sha256" "$local_app_b_apk_sha256" \
  "$expected_tun_plugin_sha256" "$fixture_script_sha256" \
  "$FIXTURE_HOST4" "$FIXTURE_HOST6" "$FIXTURE_TCP_PORT" "$FIXTURE_UDP_PORT" \
  "$MODE" "$install_ok" <<'PY'
import json
import sys

(
    output, vpn_package, app_a, app_b, vpn_uid, uid_a, uid_b,
    vpn_hash, app_a_hash, app_b_hash, plugin_hash, fixture_hash,
    fixture_host4, fixture_host6, fixture_tcp_port, fixture_udp_port,
    mode, install_ok,
) = sys.argv[1:]

def integer(value):
    try:
        return int(value)
    except ValueError:
        return -1

tuples = [
    {"stageId": "A2-1-appa-ip4-tcp", "package": app_a, "family": "ip4", "protocol": 6,
     "protocolName": "tcp", "sourceAddress": "10.111.0.2", "sourcePort": 45641, "destinationHost": fixture_host4,
     "destinationAddress": fixture_host4, "destinationPort": int(fixture_tcp_port), "repeat": 2},
    {"stageId": "A2-1-appa-ip4-udp", "package": app_a, "family": "ip4", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "10.111.0.2", "sourcePort": 45642, "destinationHost": fixture_host4,
     "destinationAddress": fixture_host4, "destinationPort": int(fixture_udp_port), "repeat": 2},
    {"stageId": "A2-1-appa-ip6-tcp", "package": app_a, "family": "ip6", "protocol": 6,
     "protocolName": "tcp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45643, "destinationHost": fixture_host6,
     "destinationAddress": fixture_host6, "destinationPort": int(fixture_tcp_port), "repeat": 2},
    {"stageId": "A2-1-appa-ip6-udp", "package": app_a, "family": "ip6", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45644, "destinationHost": fixture_host6,
     "destinationAddress": fixture_host6, "destinationPort": int(fixture_udp_port), "repeat": 2},
    {"stageId": "A2-1-appb-ip4-tcp", "package": app_b, "family": "ip4", "protocol": 6,
     "protocolName": "tcp", "sourceAddress": "10.111.0.2", "sourcePort": 45651, "destinationHost": fixture_host4,
     "destinationAddress": fixture_host4, "destinationPort": int(fixture_tcp_port), "repeat": 2},
    {"stageId": "A2-1-appb-ip4-udp", "package": app_b, "family": "ip4", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "10.111.0.2", "sourcePort": 45652, "destinationHost": fixture_host4,
     "destinationAddress": fixture_host4, "destinationPort": int(fixture_udp_port), "repeat": 2},
    {"stageId": "A2-1-appb-ip6-tcp", "package": app_b, "family": "ip6", "protocol": 6,
     "protocolName": "tcp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45653, "destinationHost": fixture_host6,
     "destinationAddress": fixture_host6, "destinationPort": int(fixture_tcp_port), "repeat": 2},
    {"stageId": "A2-1-appb-ip6-udp", "package": app_b, "family": "ip6", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45654, "destinationHost": fixture_host6,
     "destinationAddress": fixture_host6, "destinationPort": int(fixture_udp_port), "repeat": 2},
]
for item in tuples:
    item["uidContractStage"] = item["stageId"]

manifest = {
    "schema": "s139-a2-1-manifest/v1",
    "profile": "a2-1",
    "cellId": "A2-1",
    "vpnPackage": vpn_package,
    "allowedPackages": [app_a, app_b],
    "expectedVpnUid": integer(vpn_uid),
    "expectedAllowedUids": {app_a: integer(uid_a), app_b: integer(uid_b)},
    "expectedVpnApkSha256": vpn_hash,
    "expectedAppApkSha256": {app_a: app_a_hash, app_b: app_b_hash},
    "expectedTunPocPluginSha256": plugin_hash,
    "fixture": {
        "schema": "s152-a2-1-fixture/v1",
        "host4": fixture_host4,
        "host6": fixture_host6,
        "tcpPort": int(fixture_tcp_port),
        "udpPort": int(fixture_udp_port),
        "scriptSha256": fixture_hash,
        "publicInternetClaim": False,
    },
    "uidContractCellId": "A2-1",
    "mode": mode,
    "vppMode": 5,
    "installOk": install_ok == "true",
    "runtimeFiles": {app_a: "a2-1-runtime-appa.jsonl", app_b: "a2-1-runtime-appb.jsonl"},
    "tuples": tuples,
    "requiredFiles": [
        "package-list-packages-U.txt", "apk-provenance.tsv",
        "vpn-session-provenance.json", "vpp-start-provenance.json",
        "uid-attribution-contract.jsonl", "a2-1-runtime-appa.jsonl",
        "a2-1-runtime-appb.jsonl", "vpp-cli.log", "vpp-owner-resolver.log",
        "vpp-shim.log", "vpp-hev.log", "vpp-protect.log", "connectivity.txt",
        "device-build.properties", "source-provenance.properties", "cleanup.txt",
        "fixture-readiness.properties", "s152-a2-1-fixture.jsonl",
    ],
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

cleanup
trap - EXIT
set +e
python3 "$VERIFIER" \
  --manifest "$RESULT_DIR/manifest.json" \
  --evidence-dir "$RESULT_DIR" \
  --output "$RESULT_DIR/result.json"
verifier_rc=$?
set -e
exit "$verifier_rc"
