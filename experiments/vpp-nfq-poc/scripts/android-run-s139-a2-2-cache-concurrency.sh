#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2-2: concurrent two-App async UID-cache matrix.
#
# This runner only orchestrates the device and preserves raw evidence.  The
# manifest-driven verifier owns acceptance.  A2-1 owns the full eight-tuple
# matrix; A2-2 deliberately uses four fresh source ports (one per App/family)
# so the native cache capacity of four can retain every cohort member while
# the pending ledger proves overlap.

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
FIRST_WAVE_WAIT_SECONDS="${FIRST_WAVE_WAIT_SECONDS:-8}"
CONTRACT_POLL_INTERVAL="${CONTRACT_POLL_INTERVAL:-0.25}"
CLEANUP_WAIT_SECONDS="${CLEANUP_WAIT_SECONDS:-10}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-2-cache-concurrency}"

[[ "$BLOCK_OWNER_UID" == "99999" ]] || {
  echo "A2-2 requires the 99999 owner sentinel" >&2
  exit 2
}
[[ "$FIRST_WAVE_WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || {
  echo "FIRST_WAVE_WAIT_SECONDS must be a positive integer" >&2
  exit 2
}
[[ "$CONTRACT_POLL_INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
  echo "CONTRACT_POLL_INTERVAL must be a non-negative decimal" >&2
  exit 2
}

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

poll_contract_for_outcome() {
  local desired_outcome="$1"
  # Keep the poll snapshot durable as diagnostic raw evidence.  The gate is
  # decided from the native contract itself, not from elapsed time or
  # application logcat.
  adb_su "cat '$CONTRACT_PATH' 2>/dev/null || true" \
    | tr -d '\r' >"$RESULT_DIR/contract-poll.jsonl"
  python3 - "$RESULT_DIR/contract-poll.jsonl" "$app_a_uid" "$app_b_uid" \
    "$desired_outcome" <<'PY'
import json
import sys

path, uid_a_text, uid_b_text, desired_outcome = sys.argv[1:]
try:
    uid_a = int(uid_a_text)
    uid_b = int(uid_b_text)
except ValueError:
    raise SystemExit(1)

def canonical_key(family, protocol, source_address, source_port,
                  destination_address, destination_port):
    source = f"{source_address}:{source_port}"
    destination = f"{destination_address}:{destination_port}"
    first, second = sorted((source, destination))
    return f"{family}/{protocol.upper()}/{first}-{second}"

expected = {
    canonical_key("ip4", "udp", "10.111.0.2", 45741, "1.1.1.1", 53): uid_a,
    canonical_key("ip6", "udp", "fd00:111:111::2", 45742,
                  "2606:4700:4700::1111", 53): uid_a,
    canonical_key("ip4", "udp", "10.111.0.2", 45751, "1.1.1.1", 53): uid_b,
    canonical_key("ip6", "udp", "fd00:111:111::2", 45752,
                  "2606:4700:4700::1111", 53): uid_b,
}
observed = set()
try:
    with open(path, encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            key = event.get("key")
            if (event.get("outcome") == desired_outcome
                    and key in expected and event.get("uid") == expected[key]):
                observed.add(key)
except OSError:
    raise SystemExit(1)

label = "first-wave-correct-completions" if desired_outcome == "COMPLETION_ACCEPTED" \
    else "second-wave-correct-cache-hits"
print(f"{label}={len(observed)}/{len(expected)}")
raise SystemExit(0 if len(observed) == len(expected) else 1)
PY
}

poll_first_wave_contract() {
  poll_contract_for_outcome COMPLETION_ACCEPTED
}

poll_second_wave_contract() {
  poll_contract_for_outcome CACHE_HIT
}

poll_runtime_pair() {
  local family="$1"
  local minimum_count="$2"
  {
    adb_su "cat '$RUNTIME_A_PATH' 2>/dev/null || true"
    adb_su "cat '$RUNTIME_B_PATH' 2>/dev/null || true"
  } | tr -d '\r' >"$RESULT_DIR/runtime-poll.jsonl"
  python3 - "$RESULT_DIR/runtime-poll.jsonl" "$APP_PACKAGE_A" \
    "$APP_PACKAGE_B" "$family" "$minimum_count" <<'PY'
import json
import sys

path, app_a, app_b, family, minimum_text = sys.argv[1:]
try:
    minimum = int(minimum_text)
except ValueError:
    raise SystemExit(1)
expected = {
    (app_a, "A2-2-appa-{}-udp".format(family)),
    (app_b, "A2-2-appb-{}-udp".format(family)),
}
counts = {key: 0 for key in expected}
try:
    with open(path, encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue
            key = (record.get("app_package", record.get("appPackage")),
                   record.get("stage_id", record.get("stageId")))
            if (key in counts and record.get("family") == family
                    and record.get("bind_result", record.get("vpnBindResult")) == "bound"
                    and record.get("send_connect_outcome", record.get("result"))
                    == "udp_datagram_sent"
                    and record.get("tuple_attempted") is True):
                counts[key] += 1
except OSError:
    raise SystemExit(1)
print("runtime-pair {} min={} counts={}".format(family, minimum, counts))
raise SystemExit(0 if all(count >= minimum for count in counts.values()) else 1)
PY
}

wait_for_runtime_pair() {
  local family="$1"
  local minimum_count="$2"
  local deadline=$((SECONDS + FIRST_WAVE_WAIT_SECONDS))
  runtime_poll_attempts=0
  while (( SECONDS <= deadline )); do
    runtime_poll_attempts=$((runtime_poll_attempts + 1))
    if poll_runtime_pair "$family" "$minimum_count"; then
      return 0
    fi
    sleep "$CONTRACT_POLL_INTERVAL"
  done
  return 1
}

wait_for_first_wave() {
  local deadline=$((SECONDS + FIRST_WAVE_WAIT_SECONDS))
  first_wave_poll_attempts=0
  while (( SECONDS <= deadline )); do
    first_wave_poll_attempts=$((first_wave_poll_attempts + 1))
    if poll_first_wave_contract; then
      return 0
    fi
    sleep "$CONTRACT_POLL_INTERVAL"
  done
  return 1
}

wait_for_second_wave() {
  local deadline=$((SECONDS + FIRST_WAVE_WAIT_SECONDS))
  second_wave_poll_attempts=0
  while (( SECONDS <= deadline )); do
    second_wave_poll_attempts=$((second_wave_poll_attempts + 1))
    if poll_second_wave_contract; then
      return 0
    fi
    sleep "$CONTRACT_POLL_INTERVAL"
  done
  return 1
}

cleanup_done=0
cleanup_observed=0
cleanup_wait_attempts=0
cleanup_force_stop_fallback=0

write_cleanup_wait_evidence() {
  local observed="$1"
  local stop_rc="$2"
  local final_outcome="$3"
  local fallback="$4"
  python3 - "$RESULT_DIR/cleanup-wait.json" "$observed" "$stop_rc" \
    "$final_outcome" "$cleanup_wait_attempts" "$CLEANUP_WAIT_SECONDS" \
    "$fallback" <<'PY'
import json
import sys

output, observed, stop_rc, final_outcome, attempts, timeout, fallback = sys.argv[1:]
with open(output, "w", encoding="utf-8") as stream:
    json.dump({
        "schema": "s139-a2-2-cleanup-wait/v1",
        "stopRequested": True,
        "stopRequestRc": int(stop_rc),
        "cleanupObservedBeforeForceStop": observed == "true",
        "forceStopFallbackAfterTimeout": fallback == "true",
        "finalOutcome": final_outcome,
        "pollAttempts": int(attempts),
        "timeoutSeconds": int(timeout),
    }, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
}

capture_cleanup_snapshot() {
  {
    echo "processes:"
    adb_su "ps -A 2>/dev/null | grep '[v]pp\\|[s]nort-vpn' || true" \
      | tr -d '\r'
    echo "tun0:"
    adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r'
    echo "vpn:"
    adb_cmd shell dumpsys connectivity 2>/dev/null | tr -d '\r' \
      | grep -E "Vpn|tun0|$VPN_PACKAGE" || true
  } >"$RESULT_DIR/cleanup.txt"
}

poll_for_cleanup() {
  local deadline=$((SECONDS + CLEANUP_WAIT_SECONDS))
  local last_line=""
  cleanup_wait_attempts=0
  cleanup_observed=0
  cleanup_force_stop_fallback=0
  while (( SECONDS <= deadline )); do
    cleanup_wait_attempts=$((cleanup_wait_attempts + 1))
    last_line="$(adb_su "tail -n 1 '$CONTRACT_PATH' 2>/dev/null || true" \
      | tr -d '\r')"
    if grep -Eq '"outcome"[[:space:]]*:[[:space:]]*"CLEANUP"' \
      <<<"$last_line"; then
      cleanup_observed=1
      return 0
    fi
    sleep 0.25
  done
  return 1
}

cleanup() {
  if (( cleanup_done == 1 )); then
    return 0
  fi
  cleanup_done=1
  set +e
  # Stop the service through its control Activity and wait for its durable
  # CLEANUP event.  Force-stop is allowed only after that event; a timeout
  # uses a separately marked emergency fallback and remains INVALID.
  # -W waits for MainActivity delivery; clear-top reuses the existing control
  # Activity even when the traffic adapter was the foreground task.
  adb_cmd shell am start -W --activity-clear-top -n "$VPN_PACKAGE/.MainActivity" \
    --ez stop true >/dev/null 2>&1
  stop_rc=$?
  if ! poll_for_cleanup; then
    echo "CLEANUP was not observed within ${CLEANUP_WAIT_SECONDS}s; retaining raw state"
    cleanup_force_stop_fallback=1
    write_cleanup_wait_evidence false "$stop_rc" "" true
    # The bounded wait is exhausted, so perform emergency cleanup only after
    # the wait.  The failed observation remains durable and the verifier must
    # still classify this run INVALID.
    adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1
    adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1
    adb_cmd shell am force-stop "$APP_PACKAGE_B" >/dev/null 2>&1
    capture_cleanup_snapshot
    set -e
    return 0
  fi
  write_cleanup_wait_evidence true "$stop_rc" "CLEANUP" false
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1
  adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1
  adb_cmd shell am force-stop "$APP_PACKAGE_B" >/dev/null 2>&1
  capture_cleanup_snapshot
  set -e
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2-2 concurrent two-App cache matrix"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE"
echo "app_a=$APP_PACKAGE_A app_b=$APP_PACKAGE_B"
echo "activity=$TRAFFIC_ACTIVITY"
echo "mode=$MODE block_owner_uid=$BLOCK_OWNER_UID"
echo "source-ports=AppA:45741-45742 AppB:45751-45752"
echo "external-connect/reply=NON-CLAIM; logcat=DIAGNOSTIC-ONLY"

for apk in "$LOCAL_VPN_APK" "$LOCAL_APP_A_APK" "$LOCAL_APP_B_APK"; do
  [[ -f "$apk" ]] || {
    echo "missing local APK: $apk" >&2
    exit 2
  }
done

local_vpn_apk_sha256="$(sha256sum "$LOCAL_VPN_APK" | awk '{print $1}')"
local_app_a_apk_sha256="$(sha256sum "$LOCAL_APP_A_APK" | awk '{print $1}')"
local_app_b_apk_sha256="$(sha256sum "$LOCAL_APP_B_APK" | awk '{print $1}')"
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
  echo "runner=$SCRIPT_DIR/$(basename "$0")"
} >"$RESULT_DIR/source-provenance.properties"
capture_apk_provenance

echo "## request stop of any existing session and clear remote evidence"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true \
  >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_A" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE_B" >/dev/null 2>&1 || true
sleep 1
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$SHIM_PATH' '$HEV_PATH' \
  '$PROTECT_PATH' '$RECEIPT_PATH' '$FAILURE_RECEIPT_PATH' \
  '$VPP_START_RECEIPT_PATH' '$CONTRACT_PATH' '$RUNTIME_A_PATH' '$RUNTIME_B_PATH'"

echo "## start owner resolver with both deterministic packages and IPv6"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode "$MODE" \
  --es allowedPackage "$APP_PACKAGE_A,$APP_PACKAGE_B" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --ez ownerCache true \
  --ez enableIpv6 true
sleep "$START_WAIT"

launch_pids=()
launch_stages=()
launch_window_start_ns="$(date +%s%N)"

launch_tuple() {
  local package_name="$1"
  local family="$2"
  local protocol="$3"
  local source_port="$4"
  local destination_host="$5"
  local destination_port="$6"
  local stage_id="$7"
  local wave_id="$8"
  local activity="$package_name/$TRAFFIC_ACTIVITY"
  echo "## launch wave=$wave_id package=$package_name stage=$stage_id $family/$protocol $source_port -> $destination_host:$destination_port"
  adb_cmd shell am start -a com.sakamoto.snort.a2traffic.EMIT \
    -n "$activity" \
    --es a2MatrixStageId "$stage_id" \
    --es a2MatrixFamily "$family" \
    --es a2MatrixProtocol "$protocol" \
    --ei a2MatrixSourcePort "$source_port" \
    --es a2MatrixDestinationHost "$destination_host" \
    --ei a2MatrixDestinationPort "$destination_port" \
    --ei a2MatrixTimeoutMillis 1200 \
    --ei a2MatrixRepeat 1 \
    >"$RESULT_DIR/launch-$wave_id-$stage_id.log" 2>&1 &
  launch_pids+=("$!")
  launch_stages+=("$stage_id")
}

launch_pair() {
  local wave_id="$1"
  local family="$2"
  local minimum_count="$3"
  local destination_host="1.1.1.1"
  local app_a_port=45741
  local app_b_port=45751
  if [[ "$family" == ip6 ]]; then
    destination_host="2606:4700:4700::1111"
    app_a_port=45742
    app_b_port=45752
  fi
  local pair_pids=()
  launch_pids=()
  launch_tuple "$APP_PACKAGE_A" "$family" udp "$app_a_port" "$destination_host" 53 \
    A2-2-appa-"$family"-udp "$wave_id"
  launch_tuple "$APP_PACKAGE_B" "$family" udp "$app_b_port" "$destination_host" 53 \
    A2-2-appb-"$family"-udp "$wave_id"
  pair_pids=("${launch_pids[@]}")
  launch_pids=()
  for launch_pid in "${pair_pids[@]}"; do
    if ! wait "$launch_pid"; then
      launch_failures=$((launch_failures + 1))
    fi
  done
  if wait_for_runtime_pair "$family" "$minimum_count"; then
    return 0
  fi
  return 1
}

# Wave 1: submit an AppA/AppB pair per family.  Each launch has repeat=1; the
# pair's durable runtime records gate the next family so one singleTop
# Activity never receives two overlapping same-package workers.
launch_failures=0
first_wave_launch_count=0
second_wave_launch_count=0
second_wave_gate_observed=false
second_wave_poll_attempts=0
first_wave_runtime_ip4=false
first_wave_runtime_ip6=false
second_wave_runtime_ip4=false
second_wave_runtime_ip6=false
if launch_pair first ip4 1; then first_wave_runtime_ip4=true; fi
first_wave_launch_count=$((first_wave_launch_count + 2))
if launch_pair first ip6 1; then first_wave_runtime_ip6=true; fi
first_wave_launch_count=$((first_wave_launch_count + 2))
echo "first-wave-launches=$first_wave_launch_count launch_failures=$launch_failures"

# Evidence gate: do not submit wave 2 until all four wave-1 canonical keys
# have a native COMPLETION_ACCEPTED carrying the registered App UID.
first_wave_gate_observed=false
if wait_for_first_wave; then
  first_wave_gate_observed=true
  echo "first-wave-completion-gate=observed attempts=$first_wave_poll_attempts"
else
  echo "first-wave-completion-gate=timeout attempts=$first_wave_poll_attempts" >&2
fi

# Wave 2: reuse the exact four tuples once each.  A successful gate makes
# these requests cache hits; a timed-out gate intentionally leaves wave 2
# unlaunched so the verifier can classify the raw run as incomplete.
if [[ "$first_wave_gate_observed" == true ]]; then
  if launch_pair second ip4 2; then second_wave_runtime_ip4=true; fi
  second_wave_launch_count=$((second_wave_launch_count + 2))
  if launch_pair second ip6 2; then second_wave_runtime_ip6=true; fi
  second_wave_launch_count=$((second_wave_launch_count + 2))
  if wait_for_second_wave; then
    second_wave_gate_observed=true
    echo "second-wave-cache-hit-gate=observed attempts=$second_wave_poll_attempts"
  else
    echo "second-wave-cache-hit-gate=timeout attempts=$second_wave_poll_attempts" >&2
  fi
fi
launch_window_end_ns="$(date +%s%N)"
launch_count=$((first_wave_launch_count + second_wave_launch_count))
echo "launch_count=$launch_count launch_failures=$launch_failures"

python3 - "$RESULT_DIR/launch-window.json" "$launch_window_start_ns" \
  "$launch_window_end_ns" "$launch_failures" "$first_wave_launch_count" \
  "$second_wave_launch_count" "$first_wave_gate_observed" <<'PY'
import json
import sys

output, start_ns, end_ns, failures, first_count, second_count, gate = sys.argv[1:]
def integer(value):
    try:
        return int(value)
    except ValueError:
        return -1

with open(output, "w", encoding="utf-8") as stream:
    json.dump({
        "schema": "s139-a2-2-launch-window/v1",
        "launchCount": integer(first_count) + integer(second_count),
        "expectedLaunchCount": 8,
        "firstWaveLaunchCount": integer(first_count),
        "secondWaveLaunchCount": integer(second_count),
        "repeatPerLaunch": 1,
        "firstWaveCompletionGateObserved": gate == "true",
        "launchFailures": integer(failures),
        "windowStartMonotonicNs": integer(start_ns),
        "windowEndMonotonicNs": integer(end_ns),
    }, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

python3 - "$RESULT_DIR/wave-evidence.json" "$first_wave_gate_observed" \
  "$first_wave_poll_attempts" "$first_wave_launch_count" \
  "$second_wave_launch_count" "$second_wave_gate_observed" \
  "$second_wave_poll_attempts" "$launch_failures" "$app_a_uid" "$app_b_uid" \
  "$first_wave_runtime_ip4" "$first_wave_runtime_ip6" \
  "$second_wave_runtime_ip4" "$second_wave_runtime_ip6" <<'PY'
import json
import sys

(
    output, gate, attempts, first_launches, second_launches, second_gate,
    second_attempts, launch_failures, uid_a_text, uid_b_text,
    first_runtime_ip4, first_runtime_ip6, second_runtime_ip4, second_runtime_ip6,
) = sys.argv[1:]

def integer(value):
    try:
        return int(value)
    except ValueError:
        return -1

uid_a = integer(uid_a_text)
uid_b = integer(uid_b_text)
first_gate = gate == "true"
second_gate_observed = second_gate == "true"
runtime_gates = lambda ip4, ip6: {
    "ip4": ip4 == "true",
    "ip6": ip6 == "true",
}
keys = [
    {"key": "ip4/UDP/1.1.1.1:53-10.111.0.2:45741", "uid": uid_a},
    {"key": "ip6/UDP/2606:4700:4700::1111:53-fd00:111:111::2:45742", "uid": uid_a},
    {"key": "ip4/UDP/1.1.1.1:53-10.111.0.2:45751", "uid": uid_b},
    {"key": "ip6/UDP/2606:4700:4700::1111:53-fd00:111:111::2:45752", "uid": uid_b},
]
with open(output, "w", encoding="utf-8") as stream:
    json.dump({
        "schema": "s139-a2-2-two-wave/v1",
        "runtimeRecordSchema": "s139-a2-1-runtime/v1",
        "contractRecordSchema": "uid-attribution-contract/v1",
        "firstWave": {
            "launchCount": integer(first_launches),
            "repeat": 1,
            "gateObserved": first_gate,
            "gateOutcome": "COMPLETION_ACCEPTED",
            "pollAttempts": integer(attempts),
            "correctUidCompletionCount": 4 if first_gate else 0,
            "completionKeys": keys if first_gate else [],
            "runtimeGates": runtime_gates(first_runtime_ip4, first_runtime_ip6),
        },
        "secondWave": {
            "launchCount": integer(second_launches),
            "repeat": 1,
            "launched": integer(second_launches) == 4,
            "cacheHitExpected": first_gate,
            "gateObserved": second_gate_observed,
            "gateOutcome": "CACHE_HIT",
            "pollAttempts": integer(second_attempts),
            "correctUidCacheHitCount": 4 if second_gate_observed else 0,
            "cacheHitKeys": keys if second_gate_observed else [],
            "runtimeGates": runtime_gates(second_runtime_ip4, second_runtime_ip6),
        },
        "launchFailures": integer(launch_failures),
    }, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "## capture durable pre-cleanup A2-2 evidence"
capture_remote "vpn-session-provenance.json" "$RECEIPT_PATH"
capture_remote "vpn-session-provenance-failure.json" "$FAILURE_RECEIPT_PATH"
capture_remote "vpp-start-provenance.json" "$VPP_START_RECEIPT_PATH"
capture_remote "uid-attribution-contract.jsonl" "$CONTRACT_PATH"
capture_remote "a2-2-runtime-appa.jsonl" "$RUNTIME_A_PATH"
capture_remote "a2-2-runtime-appb.jsonl" "$RUNTIME_B_PATH"
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
  "$expected_tun_plugin_sha256" "$MODE" "$install_ok" <<'PY'
import json
import sys

(
    output, vpn_package, app_a, app_b, vpn_uid, uid_a, uid_b,
    vpn_hash, app_a_hash, app_b_hash, plugin_hash, mode, install_ok,
) = sys.argv[1:]

def integer(value):
    try:
        return int(value)
    except ValueError:
        return -1

tuples = [
    {"stageId": "A2-2-appa-ip4-udp", "package": app_a, "family": "ip4", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "10.111.0.2", "sourcePort": 45741,
     "destinationHost": "1.1.1.1", "destinationAddress": "1.1.1.1", "destinationPort": 53,
     "repeat": 1},
    {"stageId": "A2-2-appa-ip6-udp", "package": app_a, "family": "ip6", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45742,
     "destinationHost": "2606:4700:4700::1111", "destinationAddress": "2606:4700:4700::1111",
     "destinationPort": 53, "repeat": 1},
    {"stageId": "A2-2-appb-ip4-udp", "package": app_b, "family": "ip4", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "10.111.0.2", "sourcePort": 45751,
     "destinationHost": "1.1.1.1", "destinationAddress": "1.1.1.1", "destinationPort": 53,
     "repeat": 1},
    {"stageId": "A2-2-appb-ip6-udp", "package": app_b, "family": "ip6", "protocol": 17,
     "protocolName": "udp", "sourceAddress": "fd00:111:111::2", "sourcePort": 45752,
     "destinationHost": "2606:4700:4700::1111", "destinationAddress": "2606:4700:4700::1111",
     "destinationPort": 53, "repeat": 1},
]

manifest = {
    "schema": "s139-a2-2-manifest/v1",
    "profile": "a2-2",
    "cellId": "A2-2",
    "vpnPackage": vpn_package,
    "allowedPackages": [app_a, app_b],
    "expectedVpnUid": integer(vpn_uid),
    "expectedAllowedUids": {app_a: integer(uid_a), app_b: integer(uid_b)},
    "expectedVpnApkSha256": vpn_hash,
    "expectedAppApkSha256": {app_a: app_a_hash, app_b: app_b_hash},
    "expectedTunPocPluginSha256": plugin_hash,
    "mode": mode,
    "vppMode": 5,
    "blockOwnerUid": 99999,
    "installOk": install_ok == "true",
    "runtimeFiles": {app_a: "a2-2-runtime-appa.jsonl", app_b: "a2-2-runtime-appb.jsonl"},
    "contractFile": "uid-attribution-contract.jsonl",
    "contractFinalFile": "uid-attribution-contract-final.jsonl",
    "cleanupWaitFile": "cleanup-wait.json",
    "waveEvidenceFile": "wave-evidence.json",
    "tuples": tuples,
    "requiredFiles": [
        "package-list-packages-U.txt", "apk-provenance.tsv",
        "vpn-session-provenance.json", "vpp-start-provenance.json",
        "uid-attribution-contract.jsonl", "uid-attribution-contract-final.jsonl",
        "cleanup-wait.json",
        "contract-poll.jsonl", "runtime-poll.jsonl", "wave-evidence.json",
        "a2-2-runtime-appa.jsonl", "a2-2-runtime-appb.jsonl",
        "vpp-cli.log", "vpp-owner-resolver.log", "vpp-shim.log",
        "vpp-hev.log", "vpp-protect.log", "connectivity.txt",
        "device-build.properties", "source-provenance.properties",
        "cleanup.txt", "launch-window.json",
    ],
}
with open(output, "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "## cleanup VPN and Apps before final contract capture"
cleanup
trap - EXIT

# This capture is intentionally after cleanup's stop + force-stop sequence.
# Keep the pre-cleanup contract above untouched; the verifier compares this
# separate final snapshot's last event and settlement counters.  If the
# durable CLEANUP was not observed, cleanup() used only its post-timeout
# fallback force-stop and the missing final capture leaves the raw run INVALID.
if (( cleanup_observed != 1 )); then
  echo "## cleanup wait failed; retain raw evidence and let verifier return INVALID"
  set +e
  python3 "$VERIFIER" \
    --manifest "$RESULT_DIR/manifest.json" \
    --evidence-dir "$RESULT_DIR" \
    --output "$RESULT_DIR/result.json"
  verifier_rc=$?
  set -e
  exit "$verifier_rc"
fi
echo "## capture post-cleanup final UID contract"
capture_remote "uid-attribution-contract-final.jsonl" "$CONTRACT_PATH"

set +e
python3 "$VERIFIER" \
  --manifest "$RESULT_DIR/manifest.json" \
  --evidence-dir "$RESULT_DIR" \
  --output "$RESULT_DIR/result.json"
verifier_rc=$?
set -e
exit "$verifier_rc"
