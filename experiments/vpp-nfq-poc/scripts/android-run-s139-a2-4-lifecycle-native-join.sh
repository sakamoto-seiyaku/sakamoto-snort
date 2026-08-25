#!/usr/bin/env bash
set -euo pipefail

# S139 A2-4: real TrafficAdapter lifecycle/native resolver join.
# External underlay handover and unavailable-provider downstream admission are
# explicit non-claims of this cell.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VERIFIER="$SCRIPT_DIR/verify-s139-a2-4.py"
LOCAL_VPN_APK="${LOCAL_VPN_APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
LOCAL_APP_A_APK="${LOCAL_APP_A_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE_A="${APP_PACKAGE_A:-com.sakamoto.snort.poc.appa}"
TRAFFIC_ACTIVITY="${TRAFFIC_ACTIVITY:-com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-4-lifecycle-native-join-$(date +%Y%m%d-%H%M%S)}"
START_WAIT="${START_WAIT:-12}"
STAGE_WAIT="${STAGE_WAIT:-12}"
CLEANUP_WAIT="${CLEANUP_WAIT:-12}"
POLL_INTERVAL="${POLL_INTERVAL:-0.25}"
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
DESTINATION_HOST="${DESTINATION_HOST:-}"
DESTINATION_PORT="${DESTINATION_PORT:-$FIXTURE_UDP_PORT}"
UID_CONTRACT_CELL="A2-4"
RESOLVER_CORRELATION_SCHEMA="a2-1-resolver-cell-stage-request/v1"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR/stages"
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
    echo "controlled A2-4 fixture requires both IPv4 and IPv6 host addresses" >&2
    return 2
  }
  FIXTURE_BIND_HOST4="${FIXTURE_BIND_HOST4:-$FIXTURE_HOST4}"
  FIXTURE_BIND_HOST6="${FIXTURE_BIND_HOST6:-$FIXTURE_HOST6}"
  DESTINATION_HOST="${DESTINATION_HOST:-$FIXTURE_HOST4}"
  case "$DESTINATION_HOST,$FIXTURE_HOST4,$FIXTURE_HOST6" in
    *1.1.1.1*|*2606:4700:4700::*)
      echo "public resolver addresses are forbidden as the A2-4 fixture oracle" >&2
      return 2
      ;;
  esac
  [[ "$DESTINATION_PORT" =~ ^[1-9][0-9]{2,4}$ ]] || {
    echo "DESTINATION_PORT must be a valid non-privileged port" >&2
    return 2
  }
  [[ -f "$FIXTURE_SCRIPT" ]] || {
    echo "missing controlled A2-4 fixture script: $FIXTURE_SCRIPT" >&2
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
      echo "controlled A2-4 fixture exited before readiness" >&2
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
        "destinationHost=$DESTINATION_HOST" \
        "destinationPort=$DESTINATION_PORT" \
        "readyEvents=$ready" >"$RESULT_DIR/fixture-readiness.properties"
      return 0
    fi
    sleep 0.25
  done
  echo "controlled A2-4 fixture did not publish four ready events" >&2
  return 1
}

stop_fixture() {
  if [[ -n "$fixture_pid" ]]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
    wait "$fixture_pid" >/dev/null 2>&1 || true
    fixture_pid=""
  fi
}

require_apk_member_string() {
  local apk="$1"
  local member="$2"
  local needle="$3"
  local label="$4"
  local tmp_member
  tmp_member="$(mktemp)"
  if ! unzip -p "$apk" "$member" >"$tmp_member" 2>/dev/null; then
    rm -f "$tmp_member"
    echo "local VpnLite APK lacks $member; rebuild native/plugin artifacts" >&2
    return 2
  fi
  if ! strings "$tmp_member" | grep -F "$needle" >/dev/null; then
    rm -f "$tmp_member"
    echo "local VpnLite APK lacks $label in $member; rebuild native/plugin artifacts" >&2
    return 2
  fi
  rm -f "$tmp_member"
}

VPP_ROOT="/data/user/0/$VPN_PACKAGE/files/vpp"
VPP_STDOUT="$VPP_ROOT/logs/vpp-stdout.log"
VPP_CLI="$VPP_ROOT/logs/vpp-cli.log"
VPP_RESOLVER="$VPP_ROOT/logs/vpp-owner-resolver.log"
VPP_HEV="$VPP_ROOT/logs/vpp-hev.log"
VPP_SHIM="$VPP_ROOT/logs/vpp-shim.log"
VPN_RECEIPT="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance.json"
VPN_FAILURE="/data/user/0/$VPN_PACKAGE/files/logs/vpn-session-provenance-failure.json"
VPP_START="/data/user/0/$VPN_PACKAGE/files/logs/vpp-start-provenance.json"
CONTRACT="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
APP_RUNTIME="/data/user/0/$APP_PACKAGE_A/files/debug/a2-1-runtime.jsonl"

capture() {
  local name="$1" path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$RESULT_DIR/$name"
}

capture_to() {
  local path="$1" output="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$output"
}

wait_pattern() {
  local path="$1" regex="$2" seconds="$3"
  local deadline=$((SECONDS + seconds))
  while (( SECONDS <= deadline )); do
    adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' >"$RESULT_DIR/.poll"
    if grep -Eq "$regex" "$RESULT_DIR/.poll"; then return 0; fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

wait_app() {
  local stage="$1" port="$2"
  local deadline=$((SECONDS + STAGE_WAIT))
  while (( SECONDS <= deadline )); do
    capture_to "$APP_RUNTIME" "$RESULT_DIR/.app-poll"
    if python3 - "$RESULT_DIR/.app-poll" "$stage" "$port" "$APP_PACKAGE_A" <<'PY'
import json, sys
path, stage, port, package = sys.argv[1:]
port = int(port)
try:
    stream = open(path, encoding="utf-8", errors="replace")
except OSError:
    raise SystemExit(1)
with stream:
    for raw in stream:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if (item.get("schema") == "s139-a2-1-runtime/v1"
                and item.get("stage_id") == stage
                and item.get("app_package") == package
                and item.get("source_port") == port
                and item.get("uid", -1) >= 0
                and item.get("bind_result") == "bound"
                and item.get("tuple_attempted") is True
                and item.get("send_connect_outcome") == "udp_datagram_sent"):
            raise SystemExit(0)
raise SystemExit(1)
PY
    then return 0; fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

wait_app_count() {
  local stage="$1" port="$2" expected="$3"
  local deadline=$((SECONDS + STAGE_WAIT))
  while (( SECONDS <= deadline )); do
    capture_to "$APP_RUNTIME" "$RESULT_DIR/.app-poll"
    if python3 - "$RESULT_DIR/.app-poll" "$stage" "$port" "$expected" "$APP_PACKAGE_A" <<'PY'
import json, sys
path, stage, port, expected, package = sys.argv[1:]
port = int(port)
expected = int(expected)
count = 0
with open(path, encoding="utf-8", errors="replace") as stream:
    for raw in stream:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if (item.get("schema") == "s139-a2-1-runtime/v1"
                and item.get("stage_id") == stage
                and item.get("app_package") == package
                and item.get("source_port") == port
                and item.get("uid", -1) >= 0
                and item.get("bind_result") == "bound"
                and item.get("tuple_attempted") is True
                and item.get("send_connect_outcome") == "udp_datagram_sent"):
            count += 1
if count >= expected:
    raise SystemExit(0)
raise SystemExit(1)
PY
    then return 0; fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

wait_contract() {
  local stage="$1" outcome="$2" port="$3"
  local deadline=$((SECONDS + STAGE_WAIT))
  while (( SECONDS <= deadline )); do
    capture_to "$CONTRACT" "$RESULT_DIR/.contract-poll"
    if python3 - "$RESULT_DIR/.contract-poll" "$stage" "$outcome" "$port" <<'PY'
import json, sys
path, stage, outcome, port = sys.argv[1:]
port = int(port)
for raw in open(path, encoding="utf-8", errors="replace"):
    try:
        item = json.loads(raw)
    except json.JSONDecodeError:
        continue
    key = str(item.get("key", ""))
    if (item.get("stage_id") == stage and item.get("outcome") == outcome
            and (port < 0 or key.endswith(":{}".format(port))
                 or ":{}-".format(port) in key)):
        raise SystemExit(0)
raise SystemExit(1)
PY
    then return 0; fi
    sleep "$POLL_INTERVAL"
  done
  return 1
}

control() {
  local stage="$1"
  shift
  adb_cmd shell am start -W --activity-clear-top -n "$VPN_PACKAGE/.MainActivity" \
    --es uidContractStage "$stage" "$@" >/dev/null
}

emit() {
  local stage="$1" port="$2" timeout="$3" repeat="${4:-1}"
  if [[ -z "$timeout" ]]; then timeout=1200; fi
  adb_cmd shell am start -W -n "$APP_PACKAGE_A/$TRAFFIC_ACTIVITY" \
    -a com.sakamoto.snort.a2traffic.EMIT \
    --es a2MatrixStageId "$stage" --es a2MatrixFamily ip4 \
    --es a2MatrixProtocol udp --ei a2MatrixSourcePort "$port" \
    --es a2MatrixDestinationHost "$DESTINATION_HOST" \
    --ei a2MatrixDestinationPort "$DESTINATION_PORT" \
    --ei a2MatrixTimeoutMillis "$timeout" --ei a2MatrixRepeat "$repeat" >/dev/null
}

stage_doc() {
  local stage="$1" kind="$2" port="$3"
  python3 - "$RESULT_DIR/stages/$stage.json" "$stage" "$kind" "$port" <<'PY'
import json, sys
path, stage, kind, port = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"schema":"s139-a2-4-stage/v1", "stage_id":stage,
               "kind":kind, "source_port":int(port)}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY
}

cleanup_done=0
service_started=0

cleanup() {
  if (( cleanup_done == 1 )); then return; fi
  cleanup_done=1
  set +e
  observed=false
  fallback=false
  if (( service_started == 1 )); then
    adb_cmd shell am start -W --activity-clear-top -n "$VPN_PACKAGE/.MainActivity" \
      --ez stop true >/dev/null 2>&1
    if wait_pattern "$CONTRACT" '"outcome":"CLEANUP"' "$CLEANUP_WAIT"; then
      observed=true
    else
      fallback=true
      adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1
      adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1
    fi
  fi
  python3 - "$RESULT_DIR/cleanup-wait.json" "$observed" "$fallback" <<'PY'
import json, sys
path, observed, fallback = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"schema":"s139-a2-4-cleanup/v1",
               "cleanupObservedBeforeForceStop": observed == "true",
               "forceStopFallback": fallback == "true"}, stream,
              indent=2, sort_keys=True)
    stream.write("\n")
PY
  ps_text="$(adb_su "ps -A 2>/dev/null | grep '[v]pp\\|[s]nort-vpn' || true" | tr -d '\r')"
  tun_text="$(adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r')"
  {
    [[ -z "$ps_text" ]] && echo cleanup_no_vpp=true || echo cleanup_no_vpp=false
    [[ -z "$tun_text" ]] && echo cleanup_no_tun=true || echo cleanup_no_tun=false
    echo transport_failures=0
    [[ -z "$ps_text" ]] || printf '%s\n' "$ps_text"
    [[ -z "$tun_text" ]] || printf '%s\n' "$tun_text"
  } >"$RESULT_DIR/cleanup.txt"
  stop_fixture
  set -e
}
trap cleanup EXIT

start_fixture
echo "# SAKAMOTO-139 A2-4 lifecycle/native join"
echo "adb_serial=$(adb_target_desc)"
echo "mode=vpp-hev-owner-resolver owner-cache=false"
echo "destination=$DESTINATION_HOST:$DESTINATION_PORT"
echo "resolverCorrelationSchema=$RESOLVER_CORRELATION_SCHEMA"
echo "external-handover=NON-CLAIM external-admission=NON-CLAIM"

[[ -f "$LOCAL_VPN_APK" && -f "$LOCAL_APP_A_APK" ]] || exit 2
local_vpn_sha="$(sha256sum "$LOCAL_VPN_APK" | awk '{print $1}')"
local_app_sha="$(sha256sum "$LOCAL_APP_A_APK" | awk '{print $1}')"
plugin_sha="$(unzip -p "$LOCAL_VPN_APK" assets/vpp-tun-poc-plugin.sha256 2>/dev/null | tr -d '\r\n')"
plugin_member="$(unzip -Z1 "$LOCAL_VPN_APK" | awk '/lib\/[^/]+\/libtun_poc_plugin\.so$/ {print; exit}')"
[[ "$plugin_sha" =~ ^[0-9a-f]{64}$ && -n "$plugin_member" ]] || exit 2
require_apk_member_string "$LOCAL_VPN_APK" \
  "lib/arm64-v8a/libvpnfdprobe.so" \
  "cell=%s stage=%s request=%llu" \
  "S156 resolver cell/stage/request schema"
require_apk_member_string "$LOCAL_VPN_APK" \
  "lib/arm64-v8a/libtun_poc_plugin.so" \
  "cell %s stage %s request %llu" \
  "S156 native resolver cell/stage/request schema"
cp "$LOCAL_VPN_APK" "$RESULT_DIR/local-vpn.apk"
cp "$LOCAL_APP_A_APK" "$RESULT_DIR/local-appa.apk"

set +e
adb_cmd install -r "$LOCAL_VPN_APK" >"$RESULT_DIR/install-vpn.log"
vpn_install_rc=$?
adb_cmd install -r "$LOCAL_APP_A_APK" >"$RESULT_DIR/install-appa.log"
app_install_rc=$?
set -e
packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-before-refresh.txt"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" 'index($0,pkg)==1 {print $2; exit}' <<<"$packages" | tr -d '[:space:]')"
app_uid="$(awk -F'uid:' -v pkg="package:$APP_PACKAGE_A" 'index($0,pkg)==1 {print $2; exit}' <<<"$packages" | tr -d '[:space:]')"
[[ "$vpn_uid" =~ ^[0-9]+$ && "$app_uid" =~ ^[0-9]+$ ]] || exit 2
printf 'vpnUid=%s\nappUid=%s\n' "$vpn_uid" "$app_uid" >"$RESULT_DIR/uid-map-before-refresh.properties"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
adb_su "rm -f '$VPP_STDOUT' '$VPP_CLI' '$VPP_RESOLVER' '$VPP_HEV' '$VPP_SHIM' '$VPN_RECEIPT' '$VPN_FAILURE' '$VPP_START' '$CONTRACT' '$APP_RUNTIME'"

adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" --ez start true \
  --es mode vpp-hev-owner-resolver --es allowedPackage "$APP_PACKAGE_A" \
  --ei blockOwnerUid 99999 --ez ownerCache false --ez enableIpv6 false >/dev/null
service_started=1
wait_pattern "$VPP_START" '"vppMode":5.*"rc":0' "$START_WAIT" || true
capture vpn-session-provenance-start.json "$VPN_RECEIPT"
capture vpp-start-provenance-start.json "$VPP_START"

control A2-4-baseline
stage_doc A2-4-baseline baseline 45901
emit A2-4-baseline 45901 1200 2
wait_app_count A2-4-baseline 45901 2 || true
wait_contract A2-4-baseline COMPLETION_ACCEPTED 45901 || true
wait_contract A2-4-baseline CACHE_HIT 45901 || true

control A2-4-baseline-hit
stage_doc A2-4-baseline-hit baseline-hit 45901
emit A2-4-baseline-hit 45901 1200
wait_app A2-4-baseline-hit 45901 || true
wait_contract A2-4-baseline-hit CACHE_HIT 45901 || true

adb_cmd install -r "$LOCAL_APP_A_APK" >"$RESULT_DIR/install-appa-refresh.log" 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
adb_cmd shell cmd package list packages -U >"$RESULT_DIR/package-list-after-refresh.txt" 2>&1 || true
control A2-4-refresh --ez uidContractRefreshApp true
stage_doc A2-4-refresh refresh 45901
emit A2-4-refresh 45901 1200 2
wait_app_count A2-4-refresh 45901 2 || true
wait_contract A2-4-refresh COMPLETION_ACCEPTED 45901 || true
wait_contract A2-4-refresh CACHE_HIT 45901 || true

control A2-4-refresh-hit
stage_doc A2-4-refresh-hit refresh-hit 45901
emit A2-4-refresh-hit 45901 1200
wait_app A2-4-refresh-hit 45901 || true
wait_contract A2-4-refresh-hit CACHE_HIT 45901 || true

adb_cmd shell am start -W --activity-clear-top -n "$VPN_PACKAGE/.MainActivity" \
  --ez stop true >/dev/null 2>&1 || true
wait_pattern "$CONTRACT" '"outcome":"CLEANUP"' "$CLEANUP_WAIT" || true
capture contract-before-restart.jsonl "$CONTRACT"
capture resolver-before-restart.log "$VPP_RESOLVER"
capture vpp-cli-before-restart.log "$VPP_CLI"
capture vpp-stdout-before-restart.log "$VPP_STDOUT"
capture vpn-session-provenance-before-restart.json "$VPN_RECEIPT"
capture vpp-start-provenance-before-restart.json "$VPP_START"
adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true

adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" --ez start true \
  --es mode vpp-hev-owner-resolver --es allowedPackage "$APP_PACKAGE_A" \
  --ei blockOwnerUid 99999 --ez ownerCache false --ez enableIpv6 false >/dev/null
wait_pattern "$VPP_START" '"vppMode":5.*"rc":0' "$START_WAIT" || true
capture vpn-session-provenance-restart.json "$VPN_RECEIPT"
capture vpp-start-provenance-restart.json "$VPP_START"
control A2-4-network-restart --ez uidContractRefreshNetwork true
stage_doc A2-4-network-restart network-restart 45902
emit A2-4-network-restart 45902 1200 2
wait_app_count A2-4-network-restart 45902 2 || true
wait_contract A2-4-network-restart COMPLETION_ACCEPTED 45902 || true
wait_contract A2-4-network-restart CACHE_HIT 45902 || true

control A2-4-unavailable --ez uidContractUnavailable true
stage_doc A2-4-unavailable unavailable 45903
emit A2-4-unavailable 45903 1200
wait_app A2-4-unavailable 45903 || true
wait_contract A2-4-unavailable LOOKUP_UNAVAILABLE 45903 || true

control A2-4-restore-miss --ez uidContractUnavailable false
stage_doc A2-4-restore-miss restore-miss 45903
emit A2-4-restore-miss 45903 1200 2
wait_app_count A2-4-restore-miss 45903 2 || true
wait_contract A2-4-restore-miss COMPLETION_ACCEPTED 45903 || true
wait_contract A2-4-restore-miss CACHE_HIT 45903 || true

control A2-4-restore-hit
stage_doc A2-4-restore-hit restore-hit 45903
emit A2-4-restore-hit 45903 1200
wait_app A2-4-restore-hit 45903 || true
wait_contract A2-4-restore-hit CACHE_HIT 45903 || true

control A2-4-runtime-stale --ei uidContractCompletionDelayMillis 1500
stage_doc A2-4-runtime-stale runtime-stale 45904
emit A2-4-runtime-stale 45904 200
if wait_contract A2-4-runtime-stale MISS_SUBMITTED 45904; then
  control A2-4-runtime-stale --ez uidContractRestartGeneration true
  wait_contract A2-4-runtime-stale COMPLETION_STALE 45904 || true
fi
control A2-4-runtime-stale --ei uidContractCompletionDelayMillis 0

# Settle the real VPN/service before taking the final evidence snapshot.  The
# verifier must see the cleanup ledger and Java CLEANUP event in the same
# bundle, while the EXIT trap remains only a fallback for an interrupted run.
cleanup
trap - EXIT

capture app-runtime.jsonl "$APP_RUNTIME"
capture uid-attribution-contract.jsonl "$CONTRACT"
capture vpp-owner-resolver.log "$VPP_RESOLVER"
capture vpp-cli.log "$VPP_CLI"
capture vpp-stdout.log "$VPP_STDOUT"
capture vpp-hev.log "$VPP_HEV"
capture vpp-shim.log "$VPP_SHIM"
capture vpn-session-provenance.json "$VPN_RECEIPT"
capture vpp-start-provenance.json "$VPP_START"
cat "$RESULT_DIR/resolver-before-restart.log" "$RESULT_DIR/vpp-owner-resolver.log" \
  >"$RESULT_DIR/vpp-owner-resolver-aggregate.log"
cat "$RESULT_DIR/vpp-cli-before-restart.log" "$RESULT_DIR/vpp-cli.log" \
  >"$RESULT_DIR/vpp-cli-aggregate.log"

printf 'vpnApkSha256\t%s\nappApkSha256\t%s\npluginSha256\t%s\npluginMember\t%s\ninstalledVpnApkSha256\t%s\ninstalledAppApkSha256\t%s\nvpnApkPath\tlocal-vpn.apk\nappApkPath\tlocal-appa.apk\n' \
  "$local_vpn_sha" "$local_app_sha" "$plugin_sha" "$plugin_member" "$local_vpn_sha" "$local_app_sha" \
  >"$RESULT_DIR/apk-provenance.tsv"

python3 - "$RESULT_DIR/install-provenance.json" "$vpn_install_rc" "$app_install_rc" <<'PY'
import json, sys
path, vpn, app = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump({"vpnInstallRc":int(vpn), "appInstallRc":int(app),
               "vpnInstallOutcome":"Success" if int(vpn)==0 else "Failed",
               "appInstallOutcome":"Success" if int(app)==0 else "Failed"},
              stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

cat >"$RESULT_DIR/source-provenance.properties" <<EOF
gitHead=$(git -C "$REPO_ROOT" rev-parse HEAD)
gitDirty=$( [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]] && echo true || echo false )
uidContractCellId=$UID_CONTRACT_CELL
resolverCorrelationSchema=$RESOLVER_CORRELATION_SCHEMA
fixtureScriptSha256=$(sha256sum "$FIXTURE_SCRIPT" | awk '{print $1}')
fixtureHost4=$FIXTURE_HOST4
fixtureHost6=$FIXTURE_HOST6
fixtureTcpPort=$FIXTURE_TCP_PORT
fixtureUdpPort=$FIXTURE_UDP_PORT
destinationHost=$DESTINATION_HOST
destinationPort=$DESTINATION_PORT
vpnApkSha256=$local_vpn_sha
appApkSha256=$local_app_sha
pluginSha256=$plugin_sha
runner=$SCRIPT_DIR/$(basename "$0")
verifierSha256=$(sha256sum "$VERIFIER" | awk '{print $1}')
EOF

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
printf '%s\n' "$packages" >"$RESULT_DIR/package-list-final.txt"

python3 - "$RESULT_DIR/manifest.json" "$vpn_uid" "$app_uid" "$local_vpn_sha" "$local_app_sha" "$plugin_sha" "$plugin_member" "$DESTINATION_HOST" "$DESTINATION_PORT" "$FIXTURE_HOST4" "$FIXTURE_HOST6" "$FIXTURE_TCP_PORT" "$FIXTURE_UDP_PORT" "$RESOLVER_CORRELATION_SCHEMA" <<'PY'
import json, sys
(
    out, vpn_uid, app_uid, vpn_sha, app_sha, plugin_sha, plugin_member,
    destination_host, destination_port, fixture_host4, fixture_host6,
    fixture_tcp_port, fixture_udp_port, resolver_correlation_schema,
) = sys.argv[1:]
stages = [
 ("A2-4-baseline","baseline",45901,["MISS_SUBMITTED","COMPLETION_ACCEPTED","CACHE_HIT"],"sequence"),
 ("A2-4-baseline-hit","baseline-hit",45901,["CACHE_HIT"],"hit"),
 ("A2-4-refresh","refresh",45901,["MISS_SUBMITTED","COMPLETION_ACCEPTED","CACHE_HIT"],"sequence"),
 ("A2-4-refresh-hit","refresh-hit",45901,["CACHE_HIT"],"hit"),
 ("A2-4-network-restart","network-restart",45902,["MISS_SUBMITTED","COMPLETION_ACCEPTED","CACHE_HIT"],"sequence"),
 ("A2-4-unavailable","unavailable",45903,["LOOKUP_UNAVAILABLE"],"unavailable"),
 ("A2-4-restore-miss","restore-miss",45903,["MISS_SUBMITTED","COMPLETION_ACCEPTED","CACHE_HIT"],"sequence"),
 ("A2-4-restore-hit","restore-hit",45903,["CACHE_HIT"],"hit"),
 ("A2-4-runtime-stale","runtime-stale",45904,["MISS_SUBMITTED","COMPLETION_STALE"],"stale"),
]
manifest = {
 "schema":"s139-a2-4-manifest/v1","profile":"a2-4","cellId":"A2-4",
 "architecture_interruption":False,"mode":"vpp-hev-owner-resolver","vppMode":5,
 "uidContractCellId":"A2-4",
 "resolverCorrelationSchema":resolver_correlation_schema,
 "fixture":{"schema":"s152-a2-1-fixture/v1","host4":fixture_host4,
   "host6":fixture_host6,"tcpPort":int(fixture_tcp_port),
   "udpPort":int(fixture_udp_port),"publicInternetClaim":False},
 "vpnPackage":"com.sakamoto.snort.vpnlite","appPackage":"com.sakamoto.snort.poc.appa",
 "expectedVpnUid":int(vpn_uid),"expectedAllowedUid":int(app_uid),
 "registration":{"status":"registered","appPackage":"com.sakamoto.snort.poc.appa",
   "expectedAllowedUid":int(app_uid),"mode":"vpp-hev-owner-resolver","vppMode":5},
 "family":"ip4","protocol":"udp","destinationHost":destination_host,
 "destinationPort":int(destination_port),
 "vpnProvenance":"vpn-session-provenance.json","vppStartProvenance":"vpp-start-provenance.json",
 "apkProvenanceFile":"apk-provenance.tsv","installProvenanceFile":"install-provenance.json",
 "apkProvenance":{"vpnApkSha256":vpn_sha,"appApkSha256":app_sha,"pluginSha256":plugin_sha,
   "installedVpnApkSha256":vpn_sha,"installedAppApkSha256":app_sha,
   "vpnApkPath":"local-vpn.apk","appApkPath":"local-appa.apk","pluginMember":plugin_member},
 "evidence":{"appRuntime":"app-runtime.jsonl","contract":"uid-attribution-contract.jsonl",
   "resolver":"vpp-owner-resolver-aggregate.log","cli":"vpp-cli-aggregate.log",
   "cleanup":"cleanup-wait.json","cleanupLedger":"cleanup.txt","stageDir":"stages"},
 "stages":[{"stage_id":sid,"kind":kind,"sourcePort":port,
   "contractOutcomes":outs,"nativeObservation":native}
   for sid,kind,port,outs,native in stages],
 "staleNativeJoinRequired":False,
 "claims":{"externalHandover":False,"externalAdmission":False,
   "publicInternet":False}
}
with open(out, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

set +e
python3 "$VERIFIER" --manifest "$RESULT_DIR/manifest.json" \
  --evidence-dir "$RESULT_DIR" --output "$RESULT_DIR/result.json"
rc=$?
set -e
echo "result_dir=$RESULT_DIR"
exit "$rc"
