#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2-0: one durable VpnService session provenance cell.
# This runner owns capture and cleanup only.  Acceptance is delegated to
# verify-s139-a2.py; logcat is retained as diagnostic evidence and is never a
# provenance gate.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VERIFIER="$SCRIPT_DIR/verify-s139-a2.py"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
ALLOWED_PACKAGE="${ALLOWED_PACKAGE:-com.sakamoto.snort.androidruntime}"
TRIGGER_ACTIVITY="${TRIGGER_ACTIVITY:-com.sakamoto.snort.androidruntime/.DebugControlActivity}"
MODE="${MODE:-vpp-hev-owner-resolver}"
HOST="${HOST:-1.1.1.1}"
PORT="${PORT:-53}"
SOURCE_PORT="${SOURCE_PORT:-45630}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-0-session-provenance}"

VPP_ROOT="/data/user/0/$VPN_PACKAGE/files/vpp"
VPP_CLI_PATH="$VPP_ROOT/logs/vpp-cli.log"
RESOLVER_PATH="$VPP_ROOT/logs/vpp-owner-resolver.log"
SHIM_PATH="$VPP_ROOT/logs/vpp-shim.log"
HEV_PATH="$VPP_ROOT/logs/vpp-hev.log"
RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance.json"
FAILURE_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance-failure.json"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
RUNTIME_PROBE_PATH="/data/user/0/$ALLOWED_PACKAGE/files/debug/udp-traffic-probe.properties"

mkdir -p "$RESULT_DIR"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

capture_remote() {
  local name="$1"
  local path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$RESULT_DIR/$name"
}

capture_apk_provenance() {
  : >"$RESULT_DIR/apk-provenance.tsv"
  local package_name path line digest
  for package_name in "$VPN_PACKAGE" "$ALLOWED_PACKAGE"; do
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
  adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null 2>&1
  {
    echo "processes:"
    adb_su "ps -A 2>/dev/null | grep '[v]pp\|[s]nort-vpn' || true" | tr -d '\r'
    echo "tun0:"
    adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r'
    echo "vpn:"
    adb_cmd shell dumpsys connectivity 2>/dev/null \
      | tr -d '\r' | grep -E "Vpn|tun0|$VPN_PACKAGE" || true
  } >"$RESULT_DIR/cleanup.txt"
  set -e
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2-0 session provenance"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE allowed_package=$ALLOWED_PACKAGE"
echo "mode=$MODE tuple=$HOST:$PORT source_port=$SOURCE_PORT"
echo "external-forwarding=NON-CLAIM; logcat=DIAGNOSTIC-ONLY"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-packages-U.txt"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$ALLOWED_PACKAGE" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
vpn_uid="${vpn_uid//[[:space:]]/}"
allowed_uid="${allowed_uid//[[:space:]]/}"
[[ "$vpn_uid" =~ ^[0-9]+$ ]] || vpn_uid=-1
[[ "$allowed_uid" =~ ^[0-9]+$ ]] || allowed_uid=-1
echo "vpn_uid=$vpn_uid allowed_uid=$allowed_uid"

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
  echo "runner=$SCRIPT_DIR/$(basename "$0")"
} >"$RESULT_DIR/source-provenance.properties"
capture_apk_provenance

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$SHIM_PATH' '$HEV_PATH' \
  '$RECEIPT_PATH' '$FAILURE_RECEIPT_PATH' '$CONTRACT_PATH' '$RUNTIME_PROBE_PATH'"

echo "## start VpnService"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode "$MODE" \
  --es allowedPackage "$ALLOWED_PACKAGE" \
  --ei blockOwnerUid 99999 \
  --ez ownerCache true \
  --ez enableIpv6 false
sleep "$START_WAIT"

echo "## trigger one real allowed-package UDP tuple"
adb_cmd shell am start -n "$TRIGGER_ACTIVITY" \
  --ez debugUdpTraffic true \
  --es debugUdpHost "$HOST" \
  --ei debugUdpPort "$PORT" \
  --ei debugUdpSourcePort "$SOURCE_PORT" \
  --ei debugUdpTimeoutMillis 1200 \
  --ez debugTrafficBindToVpn true
sleep "$PROBE_WAIT"

capture_remote "vpn-session-provenance.json" "$RECEIPT_PATH"
capture_remote "vpn-session-provenance-failure.json" "$FAILURE_RECEIPT_PATH"
capture_remote "uid-attribution-contract.jsonl" "$CONTRACT_PATH"
capture_remote "runtime-udp-traffic-probe.properties" "$RUNTIME_PROBE_PATH"
capture_remote "vpp-cli.log" "$VPP_CLI_PATH"
capture_remote "vpp-owner-resolver.log" "$RESOLVER_PATH"
capture_remote "vpp-shim.log" "$SHIM_PATH"
capture_remote "vpp-hev.log" "$HEV_PATH"

# Derived hint only; the complete VPP/resolver logs above remain authoritative.
grep -E 'last-tuple|resolver query=' \
  "$RESULT_DIR/vpp-cli.log" "$RESULT_DIR/vpp-owner-resolver.log" \
  >"$RESULT_DIR/exact-vpp-tuple.txt" || true

echo "## logcat diagnostic capture (not a verifier gate)"
adb_cmd shell logcat -d -t 500 -s SnortVpnLite:I SnortVpnService:I '*:S' \
  2>/dev/null | tr -d '\r' >"$RESULT_DIR/logcat-diagnostic.log" || true

{
  printf '{\n'
  printf '  "schema":"s139-a2-0-manifest/v1",\n'
  printf '  "profile":"a2-0",\n'
  printf '  "cellId":"A2-0",\n'
  printf '  "vpnPackage":"%s",\n' "$VPN_PACKAGE"
  printf '  "allowedPackage":"%s",\n' "$ALLOWED_PACKAGE"
  printf '  "expectedVpnUid":%s,\n' "$vpn_uid"
  printf '  "expectedAllowedUid":%s,\n' "$allowed_uid"
  printf '  "mode":"%s",\n' "$MODE"
  printf '  "family":"ip4",\n'
  printf '  "protocol":17,\n'
  printf '  "host":"%s",\n' "$HOST"
  printf '  "port":%s,\n' "$PORT"
  printf '  "sourcePort":%s,\n' "$SOURCE_PORT"
  printf '  "sourceAddress":"10.111.0.2",\n'
  printf '  "mtu":1500,\n'
  printf '  "disallowedPackage":"",\n'
  printf '  "requiredFiles":[\n'
  printf '    "package-list-packages-U.txt",\n'
  printf '    "apk-provenance.tsv",\n'
  printf '    "vpn-session-provenance.json",\n'
  printf '    "uid-attribution-contract.jsonl",\n'
  printf '    "runtime-udp-traffic-probe.properties",\n'
  printf '    "vpp-cli.log",\n'
  printf '    "vpp-owner-resolver.log",\n'
  printf '    "device-build.properties",\n'
  printf '    "source-provenance.properties",\n'
  printf '    "cleanup.txt"\n'
  printf '  ]\n'
  printf '}\n'
} >"$RESULT_DIR/manifest.json"

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
