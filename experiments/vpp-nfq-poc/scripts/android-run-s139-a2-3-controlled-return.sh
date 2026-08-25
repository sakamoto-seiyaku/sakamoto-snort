#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2-3: controlled reverse traffic through the real OI3 TUN
# ingress -> FlowStack owner -> oi3_output seam.  This runner is intentionally
# bounded: it captures raw ledgers and delegates the verdict to
# verify-s139-a2-3.py.  It does not claim an external Internet path.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VERIFIER="$SCRIPT_DIR/verify-s139-a2-3.py"

LOCAL_VPN_APK="${LOCAL_VPN_APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
LOCAL_APP_A_APK="${LOCAL_APP_A_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE_A="${APP_PACKAGE_A:-com.sakamoto.snort.poc.appa}"
TRAFFIC_ACTIVITY="${TRAFFIC_ACTIVITY:-com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
MODE="${MODE:-vpp-oi3-a2-3-return}"
STAGE_ID="${STAGE_ID:-}"
FAMILY="${FAMILY:-ip4}"
SOURCE_PORT="${SOURCE_PORT:-45841}"
DESTINATION_HOST="${DESTINATION_HOST:-10.200.0.1}"
DESTINATION_PORT="${DESTINATION_PORT:-42081}"
START_WAIT="${START_WAIT:-10}"
RETURN_WAIT="${RETURN_WAIT:-10}"
CLEANUP_WAIT_SECONDS="${CLEANUP_WAIT_SECONDS:-12}"
POLL_INTERVAL="${POLL_INTERVAL:-0.25}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-3-controlled-return}"

case "$MODE" in
  vpp-oi3-a2-3-return) VPP_MODE=25; EXPECTED_CELL=udp4 ;;
  vpp-oi3-a2-3-return6) VPP_MODE=26; EXPECTED_CELL=udp6 ;;
  *) echo "A2-3 requires vpp-oi3-a2-3-return or vpp-oi3-a2-3-return6" >&2; exit 2 ;;
esac
if [[ -z "$STAGE_ID" ]]; then
  STAGE_ID="$([[ "$MODE" == vpp-oi3-a2-3-return6 ]] && echo A2-3-udp6-return || echo A2-3-udp4-return)"
fi
EXPECTED_STAGE_ID="$([[ "$MODE" == vpp-oi3-a2-3-return6 ]] && echo A2-3-udp6-return || echo A2-3-udp4-return)"
[[ "$STAGE_ID" == "$EXPECTED_STAGE_ID" ]] || {
  echo "A2-3 stage is fixed by mode: expected $EXPECTED_STAGE_ID" >&2
  exit 2
}
if [[ "$FAMILY" == ip6 ]]; then
  [[ "$MODE" == vpp-oi3-a2-3-return6 ]] || {
    echo "ip6 requires vpp-oi3-a2-3-return6" >&2
    exit 2
  }
  [[ "$DESTINATION_HOST" == fd00:200::* ]] || {
    echo "ip6 A2-3 destination must be in fd00:200::/64" >&2
    exit 2
  }
else
  [[ "$FAMILY" == ip4 && "$MODE" == vpp-oi3-a2-3-return ]] || {
    echo "ip4 requires vpp-oi3-a2-3-return" >&2
    exit 2
  }
  [[ "$DESTINATION_HOST" == 10.200.0.* ]] || {
    echo "ip4 A2-3 destination must be in 10.200.0.0/24" >&2
    exit 2
  }
fi
[[ "$SOURCE_PORT" =~ ^[0-9]+$ && "$SOURCE_PORT" -ge 1 && "$SOURCE_PORT" -le 65535 ]] || exit 2
[[ "$DESTINATION_PORT" =~ ^[0-9]+$ && "$DESTINATION_PORT" -ge 1 && "$DESTINATION_PORT" -le 65535 ]] || exit 2
[[ "$START_WAIT" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$RETURN_WAIT" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$CLEANUP_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$POLL_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] || exit 2

VPP_ROOT="/data/user/0/$VPN_PACKAGE/files/vpp"
VPP_STDOUT_PATH="$VPP_ROOT/logs/vpp-stdout.log"
VPP_CLI_PATH="$VPP_ROOT/logs/vpp-cli.log"
VPP_LOG_PATH="$VPP_ROOT/logs/vpp.log"
VPP_OI3_PATH="$VPP_ROOT/logs/vpp-oi3-controlled.log"
RESOLVER_PATH="$VPP_ROOT/logs/vpp-owner-resolver.log"
SHIM_PATH="$VPP_ROOT/logs/vpp-shim.log"
RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance.json"
FAILURE_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance-failure.json"
VPP_START_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpp-start-provenance.json"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
APP_RETURN_PATH="/data/user/0/$APP_PACKAGE_A/files/debug/a2-3-return-runtime.jsonl"

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
  for package_name in "$VPN_PACKAGE" "$APP_PACKAGE_A"; do
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

poll_native_start() {
  local deadline=$((SECONDS + START_WAIT))
  while (( SECONDS <= deadline )); do
    capture_remote "vpp-stdout.poll.log" "$VPP_STDOUT_PATH"
    if grep -Fq "event=START stage-id=$STAGE_ID" \
        "$RESULT_DIR/vpp-stdout.poll.log"; then
      return 0
    fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

poll_app_return() {
  local deadline=$((SECONDS + RETURN_WAIT))
  while (( SECONDS <= deadline )); do
    capture_remote "app-return-poll.jsonl" "$APP_RETURN_PATH"
    if python3 - "$RESULT_DIR/app-return-poll.jsonl" "$STAGE_ID" \
        "$APP_PACKAGE_A" "$FAMILY" "$SOURCE_PORT" "$DESTINATION_PORT" <<'PY'
import json
import sys

path, stage, package_name, family, source_port, destination_port = sys.argv[1:]
source_port = int(source_port)
destination_port = int(destination_port)
try:
    with open(path, encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if (item.get("schema") == "s139-a2-3-return/v1"
                    and item.get("cell_id") == "A2-3"
                    and item.get("stage_id") == stage
                    and item.get("app_package") == package_name
                    and item.get("family") == family
                    and item.get("source_port") == source_port
                    and item.get("destination_port") == destination_port
                    and item.get("bind_result") == "bound"
                    and item.get("tuple_attempted") is True
                    and item.get("send_connect_outcome") == "udp_roundtrip_received"
                    and item.get("return_received") is True
                    and item.get("payload_hex") == item.get("received_payload_hex")
                    and item.get("payload_length") == item.get("received_length")):
                raise SystemExit(0)
except OSError:
    pass
raise SystemExit(1)
PY
    then
      return 0
    fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

write_cleanup_wait() {
  printf '{"schema":"s139-a2-3-cleanup/v1",' >"$RESULT_DIR/cleanup-wait.json"
  printf '"cleanupObservedBeforeForceStop":%s,' "$cleanup_observed" \
    >>"$RESULT_DIR/cleanup-wait.json"
  printf '"nativeCleanupObserved":%s,"contractCleanupObserved":%s,' \
    "$native_cleanup_observed" "$contract_cleanup_observed" \
    >>"$RESULT_DIR/cleanup-wait.json"
  printf '"forceStopFallback":%s,"pollAttempts":%s}\n' \
    "$force_stop_fallback" "$cleanup_poll_attempts" \
    >>"$RESULT_DIR/cleanup-wait.json"
}

cleanup_done=0
cleanup() {
  if (( cleanup_done == 1 )); then
    return 0
  fi
  cleanup_done=1
  set +e
  # Product stop supervises the VPP child with TERM/KILL and therefore can
  # legitimately bypass the OI3 test-only cleanup emitter.  A2-3 needs both
  # seams: first drive the bounded OI3 stop over the app-owned CLI control
  # bridge, then request the ordinary VPN stop so the Java UID contract and
  # Android service lifecycle settle.
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --es oi3Control stop \
    >/dev/null 2>&1
  native_cleanup_observed=false
  contract_cleanup_observed=false
  force_stop_fallback=false
  cleanup_poll_attempts=0
  local native_deadline=$((SECONDS + CLEANUP_WAIT_SECONDS))
  while (( SECONDS <= native_deadline )); do
    cleanup_poll_attempts=$((cleanup_poll_attempts + 1))
    capture_remote "vpp-stdout.cleanup-poll.log" "$VPP_STDOUT_PATH"
    if grep -Fq "event=CLEANUP" "$RESULT_DIR/vpp-stdout.cleanup-poll.log"; then
      native_cleanup_observed=true
      break
    fi
    sleep "$POLL_INTERVAL"
  done
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1
  local deadline=$((SECONDS + CLEANUP_WAIT_SECONDS))
  while (( SECONDS <= deadline )); do
    cleanup_poll_attempts=$((cleanup_poll_attempts + 1))
    capture_remote "vpp-stdout.cleanup-poll.log" "$VPP_STDOUT_PATH"
    capture_remote "contract.cleanup-poll.jsonl" "$CONTRACT_PATH"
    if grep -Fq "event=CLEANUP" "$RESULT_DIR/vpp-stdout.cleanup-poll.log"; then
      native_cleanup_observed=true
    fi
    # uid-attribution-contract uses `outcome` for lifecycle records (the
    # native ledger uses `event`).  Accept both spellings so the orderly-stop
    # gate observes the durable contract cleanup instead of forcing a stop
    # after a cleanup that already settled.
    if grep -Eq '"(event|outcome)":"CLEANUP"' \
        "$RESULT_DIR/contract.cleanup-poll.jsonl"; then
      contract_cleanup_observed=true
    fi
    if [[ "$native_cleanup_observed" == true && \
          "$contract_cleanup_observed" == true ]]; then
      break
    fi
    sleep "$POLL_INTERVAL"
  done
  cleanup_observed=false
  if [[ "$native_cleanup_observed" == true && \
        "$contract_cleanup_observed" == true ]]; then
    cleanup_observed=true
  else
    force_stop_fallback=true
    adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1
    adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1
  fi
  write_cleanup_wait
  {
    echo "processes:"
    adb_su "ps -A 2>/dev/null | grep '[v]pp\\|[s]nort-vpn' || true" | tr -d '\r'
    echo "tun0:"
    adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r'
    echo "vpn:"
    adb_cmd shell dumpsys connectivity 2>/dev/null \
      | tr -d '\r' | grep -E "Vpn|tun0|$VPN_PACKAGE" || true
  } >"$RESULT_DIR/cleanup.txt"
  set -e
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2-3 controlled reverse return"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE allowed_package=$APP_PACKAGE_A"
echo "mode=$MODE vpp_mode=$VPP_MODE cell=$EXPECTED_CELL stage=$STAGE_ID"
echo "tuple=$DESTINATION_HOST:$DESTINATION_PORT source_port=$SOURCE_PORT family=$FAMILY"
echo "external-forwarding=NON-CLAIM; logcat=DIAGNOSTIC-ONLY"

[[ -f "$LOCAL_VPN_APK" ]] || { echo "missing local VpnLite APK: $LOCAL_VPN_APK" >&2; exit 2; }
[[ -f "$LOCAL_APP_A_APK" ]] || { echo "missing local AppA APK: $LOCAL_APP_A_APK" >&2; exit 2; }
local_vpn_apk_sha256="$(sha256sum "$LOCAL_VPN_APK" | awk '{print $1}')"
local_app_a_apk_sha256="$(sha256sum "$LOCAL_APP_A_APK" | awk '{print $1}')"
oi3_plugin_asset="$(unzip -Z1 "$LOCAL_VPN_APK" \
  | awk '/lib\/[^/]+\/libhev_external_driver_poc_plugin\.so$/ { print; exit }')"
[[ -n "$oi3_plugin_asset" ]] || {
  echo "local VpnLite APK lacks the OI3 plugin asset" >&2
  exit 2
}
expected_oi3_plugin_sha256="$(unzip -p "$LOCAL_VPN_APK" "$oi3_plugin_asset" \
  | sha256sum | awk '{print $1}')"
[[ "$expected_oi3_plugin_sha256" =~ ^[0-9a-f]{64}$ ]] || {
  echo "local VpnLite APK lacks valid OI3 plugin provenance" >&2
  exit 2
}

echo "## install exact local APK inputs"
adb_cmd install -r "$LOCAL_VPN_APK" | tee "$RESULT_DIR/install-vpn.log"
adb_cmd install -r "$LOCAL_APP_A_APK" | tee "$RESULT_DIR/install-appa.log"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-packages-U.txt"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$APP_PACKAGE_A" \
  'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
vpn_uid="${vpn_uid//[[:space:]]/}"
allowed_uid="${allowed_uid//[[:space:]]/}"
[[ "$vpn_uid" =~ ^[0-9]+$ ]] || { echo "VPN UID unavailable" >&2; exit 2; }
[[ "$allowed_uid" =~ ^[0-9]+$ ]] || { echo "AppA UID unavailable" >&2; exit 2; }
echo "vpn_uid=$vpn_uid allowed_uid=$allowed_uid"

source_git_head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
source_git_dirty=false
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
  source_git_dirty=true
fi
{
  printf 'captureUtc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'captureEpoch=%s\n' "$(date -u +%s)"
  printf 'gitHead=%s\n' "$source_git_head"
  printf 'gitDirty=%s\n' "$source_git_dirty"
  printf 'vpnApkSha256=%s\n' "$local_vpn_apk_sha256"
  printf 'appAApkSha256=%s\n' "$local_app_a_apk_sha256"
  printf 'oi3PluginAsset=%s\n' "$oi3_plugin_asset"
  printf 'oi3PluginSha256=%s\n' "$expected_oi3_plugin_sha256"
  printf 'runner=%s\n' "$SCRIPT_DIR/$(basename "$0")"
  printf 'verifierSha256=%s\n' "$(sha256sum "$VERIFIER" | awk '{print $1}')"
} >"$RESULT_DIR/source-provenance.properties"
capture_apk_provenance

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_STDOUT_PATH' '$VPP_CLI_PATH' '$VPP_LOG_PATH' '$VPP_OI3_PATH' \
  '$RESOLVER_PATH' '$SHIM_PATH' '$RECEIPT_PATH' '$FAILURE_RECEIPT_PATH' \
  '$VPP_START_RECEIPT_PATH' '$CONTRACT_PATH' '$APP_RETURN_PATH'"

echo "## start VpnService in independent A2-3 return mode"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode "$MODE" \
  --es allowedPackage "$APP_PACKAGE_A" \
  --ez ownerCache false \
  --ez enableIpv6 "$([[ "$FAMILY" == ip6 ]] && echo true || echo false)"
if ! poll_native_start; then
  echo "A2-3 native START not observed within ${START_WAIT}s" >&2
fi

echo "## trigger real AppA UDP bind/send/receive on one socket"
adb_cmd shell am start -n "$APP_PACKAGE_A/$TRAFFIC_ACTIVITY" \
  -a com.sakamoto.snort.a2traffic.A2_3_RETURN \
  --ez a2Return true \
  --es a2ReturnStageId "$STAGE_ID" \
  --es a2ReturnFamily "$FAMILY" \
  --ei a2ReturnSourcePort "$SOURCE_PORT" \
  --es a2ReturnDestinationHost "$DESTINATION_HOST" \
  --ei a2ReturnDestinationPort "$DESTINATION_PORT" \
  --ei a2ReturnTimeoutMillis 3500
if poll_app_return; then
  echo "AppA same-socket return record observed"
else
  echo "AppA same-socket return record not observed within ${RETURN_WAIT}s" >&2
fi

echo "## orderly stop and durable cleanup gate"
cleanup
trap - EXIT

capture_remote "app-return-runtime.jsonl" "$APP_RETURN_PATH"
capture_remote "vpp-stdout.log" "$VPP_STDOUT_PATH"
capture_remote "vpp-cli.log" "$VPP_CLI_PATH"
capture_remote "vpp.log" "$VPP_LOG_PATH"
capture_remote "vpp-oi3-controlled.log" "$VPP_OI3_PATH"
capture_remote "vpp-owner-resolver.log" "$RESOLVER_PATH"
capture_remote "vpp-shim.log" "$SHIM_PATH"
capture_remote "vpn-session-provenance.json" "$RECEIPT_PATH"
capture_remote "vpn-session-provenance-failure.json" "$FAILURE_RECEIPT_PATH"
capture_remote "vpp-start-provenance.json" "$VPP_START_RECEIPT_PATH"
capture_remote "uid-attribution-contract.jsonl" "$CONTRACT_PATH"

python3 - "$RESULT_DIR/manifest.json" <<PY
import json
from pathlib import Path

manifest = {
    "schema": "s139-a2-3-manifest/v1",
    "profile": "a2-3",
    "cellId": "A2-3",
    "vpnPackage": "$VPN_PACKAGE",
    "allowedPackage": "$APP_PACKAGE_A",
    "expectedVpnUid": int("$vpn_uid"),
    "expectedAllowedUid": int("$allowed_uid"),
    "expectedOi3PluginSha256": "$expected_oi3_plugin_sha256",
    "oi3PluginAsset": "$oi3_plugin_asset",
    "mode": "$MODE",
    "vppMode": $VPP_MODE,
    "stageId": "$STAGE_ID",
    "family": "$FAMILY",
    "protocol": "udp",
    "sourcePort": int("$SOURCE_PORT"),
    "destinationHost": "$DESTINATION_HOST",
    "destinationPort": int("$DESTINATION_PORT"),
    "appEvidenceFile": "app-return-runtime.jsonl",
    "oi3EvidenceFile": "vpp-stdout.log",
    "contractFile": "uid-attribution-contract.jsonl",
    "cleanupFile": "cleanup-wait.json",
    "vpnReceiptFile": "vpn-session-provenance.json",
    "vppStartFile": "vpp-start-provenance.json",
    "apkProvenanceFile": "apk-provenance.tsv",
    "buildProvenanceFile": "source-provenance.properties",
    "installVpnFile": "install-vpn.log",
    "installAppAFile": "install-appa.log",
    "claims": {
        "sameSocketPayload": True,
        "canonicalOwnerReuse": True,
        "externalForwarding": False,
        "androidUidLookup": False,
    },
}
Path(__import__("sys").argv[1]).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

set +e
python3 "$VERIFIER" \
  --manifest "$RESULT_DIR/manifest.json" \
  --evidence-dir "$RESULT_DIR" \
  --output "$RESULT_DIR/result.json"
verifier_rc=$?
set -e
exit "$verifier_rc"
