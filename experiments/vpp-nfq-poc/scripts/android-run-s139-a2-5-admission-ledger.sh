#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2-5: known-UID allow/drop at the real owner-resolver -> HEV
# protect/socket seam. Each policy cell is a fresh VPN/VPP session and a
# fresh canonical tuple; aggregate counters are never used as the verdict.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VERIFIER="$SCRIPT_DIR/verify-s139-a2-5.py"

LOCAL_VPN_APK="${LOCAL_VPN_APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
LOCAL_APP_A_APK="${LOCAL_APP_A_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE_A="${APP_PACKAGE_A:-com.sakamoto.snort.poc.appa}"
TRAFFIC_ACTIVITY="${TRAFFIC_ACTIVITY:-com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
MODE="${MODE:-vpp-hev-owner-resolver}"
FAMILY="${FAMILY:-ip4}"
PROTOCOL="${PROTOCOL:-udp}"
DESTINATION_HOST="${DESTINATION_HOST:-1.1.1.1}"
DESTINATION_PORT="${DESTINATION_PORT:-53}"
ALLOW_SOURCE_PORT="${ALLOW_SOURCE_PORT:-46001}"
DROP_SOURCE_PORT="${DROP_SOURCE_PORT:-46002}"
REPEAT="${REPEAT:-2}"
START_WAIT="${START_WAIT:-12}"
TRAFFIC_WAIT="${TRAFFIC_WAIT:-12}"
CLEANUP_WAIT_SECONDS="${CLEANUP_WAIT_SECONDS:-12}"
POLL_INTERVAL="${POLL_INTERVAL:-0.25}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-5-admission-ledger-$(date -u +%Y%m%d-%H%M%S)}"

[[ "$MODE" == "vpp-hev-owner-resolver" ]] || { echo "A2-5 requires vpp-hev-owner-resolver" >&2; exit 2; }
[[ "$FAMILY" == "ip4" && "$PROTOCOL" == "udp" ]] || { echo "A2-5 runner currently registers only ip4/udp" >&2; exit 2; }
for value in "$DESTINATION_PORT" "$ALLOW_SOURCE_PORT" "$DROP_SOURCE_PORT"; do
  [[ "$value" =~ ^[0-9]+$ && "$value" -ge 1 && "$value" -le 65535 ]] || exit 2
done
[[ "$START_WAIT" =~ ^[1-9][0-9]*$ && "$TRAFFIC_WAIT" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$CLEANUP_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$POLL_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] || exit 2
[[ "$REPEAT" =~ ^[2-9][0-9]*$ && "$REPEAT" -le 16 ]] || exit 2

VPP_ROOT="/data/user/0/$VPN_PACKAGE/files/vpp"
VPP_STDOUT_PATH="$VPP_ROOT/logs/vpp-stdout.log"
VPP_CLI_PATH="$VPP_ROOT/logs/vpp-cli.log"
VPP_RESOLVER_PATH="$VPP_ROOT/logs/vpp-owner-resolver.log"
VPP_PROTECT_PATH="$VPP_ROOT/logs/vpp-protect.log"
VPP_HEV_PATH="$VPP_ROOT/logs/vpp-hev.log"
VPP_SHIM_PATH="$VPP_ROOT/logs/vpp-shim.log"
VPP_START_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpp-start-provenance.json"
VPN_RECEIPT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance.json"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
APP_EVIDENCE_PATH="/data/user/0/$APP_PACKAGE_A/files/debug/a2-1-runtime.jsonl"
SOCKS_SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_ROOT="/data/local/tmp/vpp-nfq-poc"
REMOTE_SOCKS_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
REMOTE_SOCKS_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server-a2-5.log"
REMOTE_SOCKS_PID="$REMOTE_ROOT/runtime/socks-a2-5.pid"

mkdir -p "$RESULT_DIR"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

capture_remote() {
  local out="$1" path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$out"
}

cleanup_socks_server() {
  adb_su "if [ -f '$REMOTE_SOCKS_PID' ]; then kill -TERM \$(cat '$REMOTE_SOCKS_PID') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_SOCKS_PID') 2>/dev/null || true; fi; rm -f '$REMOTE_SOCKS_PID' '$REMOTE_SOCKS_SERVER' '$REMOTE_SOCKS_LOG'" >/dev/null 2>&1 || true
}

trap cleanup_socks_server EXIT

capture_apk_provenance() {
  : >"$1/apk-provenance.tsv"
  local package_name path line digest
  for package_name in "$VPN_PACKAGE" "$APP_PACKAGE_A"; do
    while IFS= read -r line; do
      path="${line#package:}"
      [[ "$path" == /* ]] || continue
      digest="$(adb_su "sha256sum '$path' 2>/dev/null || true" | tr -d '\r' | awk 'NF { print $1; exit }')"
      printf '%s\t%s\t%s\n' "$package_name" "$path" "$digest" >>"$1/apk-provenance.tsv"
    done < <(adb_cmd shell pm path "$package_name" 2>/dev/null | tr -d '\r')
  done
}

write_stage_cleanup() {
  local dir="$1" observed="$2" native="$3" contract="$4" fallback="$5" attempts="$6"
  python3 - "$dir/cleanup-wait.json" "$observed" "$native" "$contract" "$fallback" "$attempts" <<'PY'
import json, sys
path, observed, native, contract, fallback, attempts = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"schema": "s139-a2-5-cleanup/v1",
               "cleanupObservedBeforeForceStop": observed == "true",
               "nativeCleanupObserved": native == "true",
               "contractCleanupObserved": contract == "true",
               "forceStopFallback": fallback == "true",
               "pollAttempts": int(attempts)}, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

run_stage() {
  local stage="$1" policy="$2" source_port="$3" block_uid="$4"
  local dir="$RESULT_DIR/$stage"
  mkdir -p "$dir"
  echo "## A2-5 stage=$stage policy=$policy source-port=$source_port block-uid=$block_uid"

  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
  adb_su "rm -f '$VPP_STDOUT_PATH' '$VPP_CLI_PATH' '$VPP_RESOLVER_PATH' '$VPP_PROTECT_PATH' '$VPP_HEV_PATH' '$VPP_SHIM_PATH' '$VPP_START_PATH' '$VPN_RECEIPT_PATH' '$CONTRACT_PATH' '$APP_EVIDENCE_PATH'"

  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
    --ez start true --es mode "$MODE" --es allowedPackage "$APP_PACKAGE_A" \
    --ei blockOwnerUid "$block_uid" --ez ownerCache false \
    --ez enableIpv6 false --ez oi3AppInject false

  local start_ok=false deadline=$((SECONDS + START_WAIT))
  while (( SECONDS <= deadline )); do
    capture_remote "$dir/vpp-start-poll.json" "$VPP_START_PATH"
    if grep -q '"vppMode":5' "$dir/vpp-start-poll.json" && grep -q '"rc":0' "$dir/vpp-start-poll.json"; then
      start_ok=true; break
    fi
    sleep "$POLL_INTERVAL"
  done
  echo "start_observed=$start_ok"

  # Stage control is deliberately a second lifecycle message.  Sending it
  # together with start=true constructs the attribution contract before
  # startRuntime() and was observed to leave Android's owner API returning
  # -1 for every real AppA tuple.  A2-4's proven order is start -> establish ->
  # stage control -> traffic, so make that ordering an explicit barrier here.
  adb_cmd shell am start --activity-clear-top -n "$VPN_PACKAGE/.MainActivity" \
    --es uidContractStage "$stage" >/dev/null 2>&1 || true
  local stage_control_ok=false stage_deadline=$((SECONDS + START_WAIT))
  while (( SECONDS <= stage_deadline )); do
    capture_remote "$dir/uid-attribution-contract.stage-poll.jsonl" "$CONTRACT_PATH"
    if grep -q '"outcome":"STAGE_BEGIN"' "$dir/uid-attribution-contract.stage-poll.jsonl" \
        && grep -q "\"stage_id\":\"$stage\"" "$dir/uid-attribution-contract.stage-poll.jsonl"; then
      stage_control_ok=true
      break
    fi
    sleep "$POLL_INTERVAL"
  done
  echo "stage_control_observed=$stage_control_ok"

  echo "## real AppA TrafficAdapter EMIT"
  adb_cmd shell am start -n "$APP_PACKAGE_A/$TRAFFIC_ACTIVITY" \
    -a com.sakamoto.snort.a2traffic.EMIT --ez a2Matrix true \
    --es a2MatrixStageId "$stage" --es a2MatrixFamily "$FAMILY" \
    --es a2MatrixProtocol "$PROTOCOL" --ei a2MatrixSourcePort "$source_port" \
    --es a2MatrixDestinationHost "$DESTINATION_HOST" \
    --ei a2MatrixDestinationPort "$DESTINATION_PORT" \
    --ei a2MatrixTimeoutMillis 1000 --ei a2MatrixRepeat "$REPEAT"

  local traffic_ok=false traffic_deadline=$((SECONDS + TRAFFIC_WAIT))
  while (( SECONDS <= traffic_deadline )); do
    capture_remote "$dir/app-runtime.poll.jsonl" "$APP_EVIDENCE_PATH"
    capture_remote "$dir/resolver.poll.log" "$VPP_RESOLVER_PATH"
    capture_remote "$dir/protect.poll.log" "$VPP_PROTECT_PATH"
    if grep -q "stage_id.*$stage" "$dir/app-runtime.poll.jsonl" && \
       grep -q "ledger event=POLICY_DECISION.*stage-id=$stage" "$dir/resolver.poll.log"; then
      traffic_ok=true
      if [[ "$policy" == "drop" ]] || grep -q 'ledger event=BROKER_COMPLETION' "$dir/protect.poll.log"; then
        break
      fi
    fi
    sleep "$POLL_INTERVAL"
  done
  sleep 1

  capture_remote "$dir/vpp-stdout.log" "$VPP_STDOUT_PATH"
  capture_remote "$dir/vpp-cli.log" "$VPP_CLI_PATH"
  capture_remote "$dir/vpp-owner-resolver.log" "$VPP_RESOLVER_PATH"
  capture_remote "$dir/vpp-protect.log" "$VPP_PROTECT_PATH"
  capture_remote "$dir/vpp-hev.log" "$VPP_HEV_PATH"
  capture_remote "$dir/vpp-shim.log" "$VPP_SHIM_PATH"
  capture_remote "$dir/socks5.log" "$REMOTE_SOCKS_LOG"
  capture_remote "$dir/app-runtime.jsonl" "$APP_EVIDENCE_PATH"
  capture_remote "$dir/uid-attribution-contract.jsonl" "$CONTRACT_PATH"
  capture_remote "$dir/vpn-session-provenance.json" "$VPN_RECEIPT_PATH"
  capture_remote "$dir/vpp-start-provenance.json" "$VPP_START_PATH"

  # The poll loop is only a latency optimization.  A resolver response can
  # land between the last poll and orderly stop, so the durable final files
  # are authoritative for the traffic boundary.  Do not classify a real
  # policy decision as INVALID merely because the allow-stage broker did not
  # settle inside the poll window; the verifier must report that as FAIL.
  if grep -q "stage_id.*$stage" "$dir/app-runtime.jsonl" && \
     grep -q "ledger event=POLICY_DECISION.*stage-id=$stage" "$dir/vpp-owner-resolver.log"; then
    traffic_ok=true
  fi
  echo "traffic_observed=$traffic_ok"

  echo "## orderly stop stage=$stage"
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  local native_cleanup=false contract_cleanup=false cleanup_observed=false fallback=false attempts=0
  local cleanup_deadline=$((SECONDS + CLEANUP_WAIT_SECONDS))
  while (( SECONDS <= cleanup_deadline )); do
    attempts=$((attempts + 1))
    capture_remote "$dir/vpp-cli.cleanup.log" "$VPP_CLI_PATH"
    capture_remote "$dir/contract.cleanup.jsonl" "$CONTRACT_PATH"
    if grep -q 'vpp monitor stop' "$dir/vpp-cli.cleanup.log"; then native_cleanup=true; fi
    if grep -Eq '"(event|outcome)":"CLEANUP"' "$dir/contract.cleanup.jsonl"; then contract_cleanup=true; fi
    if [[ "$native_cleanup" == true && "$contract_cleanup" == true ]]; then cleanup_observed=true; break; fi
    sleep "$POLL_INTERVAL"
  done
  if [[ "$cleanup_observed" != true ]]; then
    fallback=true
    adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
    adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
  fi
  write_stage_cleanup "$dir" "$cleanup_observed" "$native_cleanup" "$contract_cleanup" "$fallback" "$attempts"

  {
    echo "processes:"
    adb_su "ps -A 2>/dev/null | grep '[v]pp\\|[s]nort-vpn' || true" | tr -d '\r'
    echo "tun0:"
    adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r'
  } >"$dir/cleanup.txt"

  python3 - "$dir/stage.json" "$stage" "$policy" "$source_port" "$block_uid" "$start_ok" "$stage_control_ok" "$traffic_ok" "$DESTINATION_HOST" "$DESTINATION_PORT" <<'PY'
import json, sys
path, stage, policy, source, block, start, stage_control, traffic, destination_host, destination_port = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"schema": "s139-a2-5-stage/v1", "stageId": stage,
               "policy": policy, "sourcePort": int(source),
               "blockOwnerUid": int(block), "startObserved": start == "true",
               "stageControlObserved": stage_control == "true",
               "trafficObserved": traffic == "true", "family": "ip4",
               "protocol": "udp", "destinationHost": destination_host,
               "destinationPort": int(destination_port), "appEvidenceFile": "app-runtime.jsonl",
               "resolverFile": "vpp-owner-resolver.log",
               "protectFile": "vpp-protect.log", "cliFile": "vpp-cli.log",
               "stdoutFile": "vpp-stdout.log", "socksFile": "socks5.log",
               "cleanupFile": "cleanup-wait.json",
               "contractFile": "uid-attribution-contract.jsonl"}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY
}

echo "# SAKAMOTO-139 A2-5 UID allow/drop admission ledger"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE app_package=$APP_PACKAGE_A mode=$MODE"
echo "family=$FAMILY protocol=$PROTOCOL destination=$DESTINATION_HOST:$DESTINATION_PORT"

[[ -f "$LOCAL_VPN_APK" ]] || { echo "missing VpnLite APK: $LOCAL_VPN_APK" >&2; exit 2; }
[[ -f "$LOCAL_APP_A_APK" ]] || { echo "missing AppA APK: $LOCAL_APP_A_APK" >&2; exit 2; }
"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$REMOTE_SOCKS_LOG' '$REMOTE_SOCKS_PID'"
adb_cmd push "$SOCKS_SERVER_BIN" "$REMOTE_SOCKS_SERVER" >/dev/null
adb_su "chmod 755 '$REMOTE_SOCKS_SERVER'; nohup '$REMOTE_SOCKS_SERVER' >'$REMOTE_SOCKS_LOG' 2>&1 < /dev/null & echo \$! > '$REMOTE_SOCKS_PID'"
sleep 1
vpn_apk_sha256="$(sha256sum "$LOCAL_VPN_APK" | awk '{print $1}')"
app_a_apk_sha256="$(sha256sum "$LOCAL_APP_A_APK" | awk '{print $1}')"
tun_asset="$(unzip -Z1 "$LOCAL_VPN_APK" | awk '/lib\/[^/]+\/libtun_poc_plugin\.so$/ {print; exit}')"
[[ -n "$tun_asset" ]] || { echo "VpnLite APK lacks tun_poc plugin" >&2; exit 2; }
tun_plugin_sha256="$(unzip -p "$LOCAL_VPN_APK" "$tun_asset" | sha256sum | awk '{print $1}')"

adb_cmd install -r "$LOCAL_VPN_APK" | tee "$RESULT_DIR/install-vpn.log"
adb_cmd install -r "$LOCAL_APP_A_APK" | tee "$RESULT_DIR/install-appa.log"
packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-packages-U.txt"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" 'index($0,pkg)==1{print $2;exit}' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$APP_PACKAGE_A" 'index($0,pkg)==1{print $2;exit}' <<<"$packages")"
vpn_uid="${vpn_uid//[[:space:]]/}"; allowed_uid="${allowed_uid//[[:space:]]/}"
[[ "$vpn_uid" =~ ^[0-9]+$ && "$allowed_uid" =~ ^[0-9]+$ ]] || { echo "package UID resolution failed" >&2; exit 2; }
echo "vpn_uid=$vpn_uid allowed_uid=$allowed_uid"
capture_apk_provenance "$RESULT_DIR"

source_git_head="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
source_git_dirty=false
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then source_git_dirty=true; fi
{
  printf 'captureUtc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'gitHead=%s\n' "$source_git_head"
  printf 'gitDirty=%s\n' "$source_git_dirty"
  printf 'vpnApkSha256=%s\n' "$vpn_apk_sha256"
  printf 'appAApkSha256=%s\n' "$app_a_apk_sha256"
  printf 'tunPluginAsset=%s\n' "$tun_asset"
  printf 'tunPluginSha256=%s\n' "$tun_plugin_sha256"
  printf 'runner=%s\n' "$SCRIPT_DIR/$(basename "$0")"
  printf 'verifierSha256=%s\n' "$(sha256sum "$VERIFIER" | awk '{print $1}')"
} >"$RESULT_DIR/source-provenance.properties"

run_stage "A2-5-allow" "allow" "$ALLOW_SOURCE_PORT" "-1"
run_stage "A2-5-drop" "drop" "$DROP_SOURCE_PORT" "$allowed_uid"

python3 - "$RESULT_DIR/manifest.json" "$VPN_PACKAGE" "$APP_PACKAGE_A" \
    "$vpn_uid" "$allowed_uid" "$vpn_apk_sha256" "$app_a_apk_sha256" \
    "$tun_asset" "$tun_plugin_sha256" "$MODE" "$DESTINATION_HOST" "$DESTINATION_PORT" \
    "$ALLOW_SOURCE_PORT" "$DROP_SOURCE_PORT" <<'PY'
import json, sys
(path, vpn, app, vpn_uid, app_uid, vpn_sha, app_sha, asset, plugin_sha,
 mode, host, port, allow_source, drop_source) = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"schema": "s139-a2-5-manifest/v1", "profile": "a2-5",
               "cellId": "A2-5", "vpnPackage": vpn, "allowedPackage": app,
               "expectedVpnUid": int(vpn_uid), "expectedAllowedUid": int(app_uid),
               "mode": mode, "vppMode": 5, "family": "ip4", "protocol": "udp",
               "destinationHost": host, "destinationPort": int(port),
               "allowSourcePort": int(allow_source), "dropSourcePort": int(drop_source),
               "vpnApkSha256": vpn_sha, "appAApkSha256": app_sha,
               "tunPluginAsset": asset, "tunPluginSha256": plugin_sha,
               "stages": [{"stageId": "A2-5-allow", "policy": "allow",
                           "sourcePort": int(allow_source), "evidenceDir": "A2-5-allow"},
                          {"stageId": "A2-5-drop", "policy": "drop",
                           "sourcePort": int(drop_source), "evidenceDir": "A2-5-drop"}],
               "claims": {"knownUidAllowDrop": True, "externalConnect": False,
                          "internetReachability": False},
               "buildProvenanceFile": "source-provenance.properties",
               "apkProvenanceFile": "apk-provenance.tsv"}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY

set +e
python3 "$VERIFIER" --manifest "$RESULT_DIR/manifest.json" \
  --evidence-dir "$RESULT_DIR" --output "$RESULT_DIR/result.json"
verifier_rc=$?
set -e
exit "$verifier_rc"
