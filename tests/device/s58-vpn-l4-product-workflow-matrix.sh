#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-58 VPN L4 product workflow evidence matrix.
#
# This matrix closes the S58 VPN-side user workflow: product-authored L4 drop,
# VPN late attribution, Activity-derived L4 prefill, product-authored restore,
# and allowed FlowEntry evidence after restore.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s58-vpn-l4-product-workflow-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
S58_BUILD_APK="${S58_BUILD_APK:-1}"
S58_INSTALL_APK="${S58_INSTALL_APK:-1}"
S58_FORWARD_PORT="${S58_FORWARD_PORT:-60658}"
S58_CLEANUP_ON_EXIT="${S58_CLEANUP_ON_EXIT:-1}"
S58_TRAFFIC_HOST="${S58_TRAFFIC_HOST:-198.51.100.58}"
S58_TRAFFIC_PORT="${S58_TRAFFIC_PORT:-443}"
S58_SOURCE_PORT="${S58_SOURCE_PORT:-45658}"
S58_TRAFFIC_TIMEOUT_MILLIS="${S58_TRAFFIC_TIMEOUT_MILLIS:-700}"
STATE_PATH="files/runtime-state/snapshot.properties"
PROBE_RESULT_PATH="files/debug/traffic-probe.properties"
L4_PREFILL_RESULT_PATH="files/debug/l4-prefill.properties"
CONTROL_SOCKET="sucre-snort-control-vnext"

mkdir -p "$RESULT_DIR"
if [[ "${S58_MATRIX_LOGGING:-0}" != "1" ]]; then
  export S58_MATRIX_LOGGING=1
  exec > >(tee "${RESULT_DIR}/matrix.log") 2>&1
fi

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  if [[ "$S58_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
  adb_cmd forward --remove "tcp:${S58_FORWARD_PORT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

read_snapshot() {
  adb_cmd shell run-as "$PACKAGE" cat "$STATE_PATH" 2>/dev/null | tr -d '\r' || true
}

snapshot_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

package_uid() {
  local line uid
  line="$(adb_cmd shell cmd package list packages -U "$PACKAGE" 2>/dev/null | tr -d '\r' | head -n 1)"
  uid="$(printf '%s\n' "$line" | sed -n 's/.* uid:\([0-9][0-9]*\).*/\1/p')"
  if [[ "$uid" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$uid"
    return 0
  fi
  uid="$(adb_cmd shell run-as "$PACKAGE" id -u 2>/dev/null | tr -d '\r\n' || true)"
  if [[ "$uid" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$uid"
    return 0
  fi
  return 1
}

query_control_json() {
  local name="$1"
  local command="$2"
  local args="{}"
  if [[ $# -ge 3 ]]; then
    args="$3"
  fi
  python3 - "$S58_FORWARD_PORT" "$RESULT_DIR" "$name" "$command" "$args" <<'PY'
import json
import pathlib
import socket
import sys

port = int(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])
name = sys.argv[3]
command = sys.argv[4]
(result_dir / f"{name}.args.json").write_text(sys.argv[5] + "\n")
args = json.loads(sys.argv[5])

payload = json.dumps({"id": 1, "cmd": command, "args": args},
                     separators=(",", ":")).encode()
frame = str(len(payload)).encode() + b":" + payload + b","

with socket.create_connection(("127.0.0.1", port), timeout=2.5) as sock:
    sock.sendall(frame)
    digits = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise RuntimeError("eof before netstring length")
        if byte == b":":
            break
        digits += byte
    length = int(digits)
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise RuntimeError("eof in netstring body")
        body += chunk
    if sock.recv(1) != b",":
        raise RuntimeError("missing netstring comma")
    response = json.loads(body.decode())

(result_dir / f"{name}.json").write_text(
    json.dumps(response, indent=2, sort_keys=True) + "\n")
if not response.get("ok"):
    raise SystemExit(f"{command} failed: {response}")
PY
}

compact_json() {
  python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), separators=(",", ":")))'
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

obj = json.load(open(sys.argv[1]))
for part in sys.argv[2].split("."):
    obj = obj[part]
print(obj)
PY
}

delta_value() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1]))["result"]
after = json.load(open(sys.argv[2]))["result"]
print(int(after.get(sys.argv[3], 0)) - int(before.get(sys.argv[3], 0)))
PY
}

activity_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))["result"]
print(doc.get("policyDropActivity", {}).get(sys.argv[2], ""))
PY
}

allowed_activity_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))["result"]
print(doc.get("allowedFlowActivity", {}).get(sys.argv[2], ""))
PY
}

stable_l4_rule_id() {
  local uid="$1"
  local family="$2"
  local ip_protocol="$3"
  local priority="$4"
  local order="$5"
  python3 - "$uid" "$family" "$ip_protocol" "$priority" "$order" <<'PY'
import sys

uid = int(sys.argv[1])
family = 0 if sys.argv[2] == "ipv4" else 1
ip_protocol = int(sys.argv[3])
priority = int(sys.argv[4])
order = int(sys.argv[5])

def mix(hash_value, value):
    value &= 0xffffffff
    for shift in range(0, 32, 8):
        hash_value ^= (value >> shift) & 0xff
        hash_value = (hash_value * 0x100000001B3) & 0xffffffffffffffff
    return hash_value

hash_value = 0xCBF29CE484222325
for value in [uid, family, ip_protocol, priority, order]:
    hash_value = mix(hash_value, value)
rule_id = 0x5200000000000000 | (hash_value & 0x00ffffffffffffff)
print(rule_id)
PY
}

cidr_for_host() {
  printf '%s/32\n' "$1"
}

policy_evaluate_l4() {
  local uid="$1"
  local destination_ip="$2"
  python3 - "$uid" "$destination_ip" "$S58_TRAFFIC_PORT" <<'PY'
import json
import sys

uid = int(sys.argv[1])
destination_ip = sys.argv[2]
destination_port = int(sys.argv[3])
print(json.dumps({
    "linuxUid": uid,
    "networkContext": 0,
    "family": "ipv4",
    "direction": "output",
    "ipProtocol": 6,
    "sourceIp": "10.111.0.2",
    "destinationIp": destination_ip,
    "sourcePort": 40000,
    "destinationPort": destination_port,
    "portsAvailable": True,
}, separators=(",", ":")))
PY
}

wait_eval() {
  local uid="$1"
  local expected_verdict="$2"
  local expected_stage="$3"
  local expected_rule="$4"
  local name="$5"
  local args verdict stage rule
  for _ in $(seq 1 20); do
    args="$(policy_evaluate_l4 "$uid" "$S58_TRAFFIC_HOST")"
    printf '%s\n' "$args" >"${RESULT_DIR}/${name}.shell_args.json"
    query_control_json "$name" "POLICY.EVALUATE" "$args" \
      >"${RESULT_DIR}/${name}.query.log" 2>&1 || true
    if [[ -f "${RESULT_DIR}/${name}.json" ]]; then
      verdict="$(json_field "${RESULT_DIR}/${name}.json" result.verdict || true)"
      stage="$(json_field "${RESULT_DIR}/${name}.json" result.stage || true)"
      rule="$(json_field "${RESULT_DIR}/${name}.json" result.ruleId || true)"
      if [[ "$verdict" == "$expected_verdict" && "$stage" == "$expected_stage" \
          && "$rule" == "$expected_rule" ]]; then
        kv "${name}.evaluateWinner" "$verdict/$stage/rule=$rule"
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

request_product_l4_rule() {
  local uid="$1"
  local action="$2"
  local destination_cidr
  destination_cidr="$(cidr_for_host "$S58_TRAFFIC_HOST")"
  adb_cmd shell am start -n "$ACTIVITY" \
    --es debugSetL4RuleSubject "android.uid:${uid}" \
    --es debugSetL4RuleFamily ipv4 \
    --es debugSetL4RuleDestinationCidr "$destination_cidr" \
    --ei debugSetL4RuleIpProtocol 6 \
    --es debugSetL4RuleDirection output \
    --es debugSetL4RuleAction "$action" \
    --ei debugSetL4RulePriority 10 \
    --ei debugSetL4RuleOrder 0 \
    --ei debugSetL4RuleDestinationPortFirst "$S58_TRAFFIC_PORT" \
    --ei debugSetL4RuleDestinationPortLast "$S58_TRAFFIC_PORT" \
    >"${RESULT_DIR}/product_l4_${action}.intent.log" 2>&1
}

attribution_apply_args() {
  local uid="$1"
  python3 - "$uid" "$S58_TRAFFIC_HOST" "$S58_TRAFFIC_PORT" "$S58_SOURCE_PORT" <<'PY'
import json
import sys

uid = int(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])
source_port = int(sys.argv[4])
print(json.dumps({
    "uidKnown": False,
    "networkContext": 0,
    "family": "ipv4",
    "direction": "output",
    "ipProtocol": 6,
    "sourceIp": "10.111.0.2",
    "destinationIp": host,
    "sourcePort": source_port,
    "destinationPort": port,
    "portsAvailable": True,
    "resolvedLinuxUid": uid,
}, separators=(",", ":")))
PY
}

run_debug_probe() {
  local label="$1"
  adb_cmd shell run-as "$PACKAGE" rm -f "$PROBE_RESULT_PATH" 2>/dev/null || true
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugTraffic true \
    --es debugTrafficHost "$S58_TRAFFIC_HOST" \
    --ei debugTrafficPort "$S58_TRAFFIC_PORT" \
    --ei debugTrafficSourcePort "$S58_SOURCE_PORT" \
    --ei debugTrafficTimeoutMillis "$S58_TRAFFIC_TIMEOUT_MILLIS" \
    >"${RESULT_DIR}/${label}.intent.log" 2>&1
  for _ in $(seq 1 30); do
    adb_cmd shell run-as "$PACKAGE" cat "$PROBE_RESULT_PATH" \
      2>/dev/null | tr -d '\r' >"${RESULT_DIR}/${label}.probe.properties" || true
    if grep -Fxq "sourcePort=${S58_SOURCE_PORT}" "${RESULT_DIR}/${label}.probe.properties"; then
      kv "${label}.probeResult" "${RESULT_DIR#${repo_root}/}/${label}.probe.properties"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

probe_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 } END { if (!found) exit 1 }' "$file"
}

run_debug_l4_prefill() {
  local label="$1"
  adb_cmd shell run-as "$PACKAGE" rm -f "$L4_PREFILL_RESULT_PATH" 2>/dev/null || true
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugL4PrefillFromActivity true \
    --es debugTrafficHost "$S58_TRAFFIC_HOST" \
    --ei debugTrafficPort "$S58_TRAFFIC_PORT" \
    >"${RESULT_DIR}/${label}.l4_prefill.intent.log" 2>&1
  for _ in $(seq 1 30); do
    adb_cmd shell run-as "$PACKAGE" cat "$L4_PREFILL_RESULT_PATH" \
      2>/dev/null | tr -d '\r' >"${RESULT_DIR}/${label}.l4_prefill.properties" || true
    if grep -Fxq "host=${S58_TRAFFIC_HOST}" "${RESULT_DIR}/${label}.l4_prefill.properties"; then
      kv "${label}.l4PrefillResult" "${RESULT_DIR#${repo_root}/}/${label}.l4_prefill.properties"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

prefill_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 } END { if (!found) exit 1 }' "$file"
}

wait_for_status_delta() {
  local before="$1"
  local out_name="$2"
  local key="$3"
  local min_delta="$4"
  local attempts="${5:-30}"
  local after="${RESULT_DIR}/${out_name}.json"
  for _ in $(seq 1 "$attempts"); do
    if query_control_json "$out_name" "VPN_TUN.STATUS" \
        >"${RESULT_DIR}/${out_name}.query.log" 2>&1; then
      if [[ "$(delta_value "$before" "$after" "$key")" -ge "$min_delta" ]]; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-58-vpn-l4-product-workflow"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "productActivityPrefillVpnEvidence" "claimed"
kv "restoreAllowedFlowEntryEvidence" "claimed"

section "build_install"
if [[ "$S58_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash app/android-runtime/scripts/build-debug-apk.sh"
  (cd "$repo_root" && bash app/android-runtime/scripts/build-debug-apk.sh) \
    >"${RESULT_DIR}/build-debug-apk.log" 2>&1
  kv "build.result" "PASS"
fi
[[ -f "$APK" ]] || {
  kv "apk.exists" "false"
  echo "missing APK: $APK" >&2
  exit 1
}
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$(sha256sum "$APK" | awk '{print $1}')"
if [[ "$S58_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi
uid="$(package_uid || true)"
[[ "$uid" =~ ^[0-9]+$ ]] || {
  kv "packageUid" "UNAVAILABLE"
  exit 1
}
kv "packageUid" "$uid"
rule_id="$(stable_l4_rule_id "$uid" ipv4 6 10 0)"
destination_cidr="$(cidr_for_host "$S58_TRAFFIC_HOST")"
kv "traffic" "$S58_TRAFFIC_HOST:$S58_TRAFFIC_PORT"
kv "sourcePort" "$S58_SOURCE_PORT"
kv "stableRuleId" "$rule_id"

section "start_vpn"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile vpn \
  >"${RESULT_DIR}/start.intent.log" 2>&1
state=""
for _ in $(seq 1 45); do
  state="$(read_snapshot)"
  printf '%s\n' "$state" >"${RESULT_DIR}/snapshot.running"
  if grep -Fxq "state=running" <<<"$state" \
      && grep -Fxq "profile=vpn" <<<"$state" \
      && grep -Fxq "health=ok" <<<"$state" \
      && grep -Fxq "coreHealth=ok" <<<"$state" \
      && grep -Fxq "adapterReadiness=vpn-tun-hev" <<<"$state"; then
    break
  fi
  sleep 1
done
if ! grep -Fxq "state=running" <<<"$state" \
    || ! grep -Fxq "profile=vpn" <<<"$state" \
    || ! grep -Fxq "health=ok" <<<"$state" \
    || ! grep -Fxq "coreHealth=ok" <<<"$state" \
    || ! grep -Fxq "adapterReadiness=vpn-tun-hev" <<<"$state"; then
  kv "start.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.running" >&2
  exit 1
fi
kv "start.result" "PASS"
kv "snapshot.pid" "$(printf '%s\n' "$state" | snapshot_value pid)"

section "control"
adb_cmd forward "tcp:${S58_FORWARD_PORT}" "localabstract:${CONTROL_SOCKET}" \
  >"${RESULT_DIR}/adb-forward.log" 2>&1
query_control_json "hello" "HELLO"
python3 - "${RESULT_DIR}/hello.json" <<'PY'
import json
import sys

caps = set(json.load(open(sys.argv[1]))["result"]["capabilities"])
required = {
    "packet-adapter-vpn-tun-hev",
    "packet-policy-control",
    "vpn-tun-runtime-counters",
    "vpn-tun-attribution-control",
}
missing = sorted(required - caps)
if missing:
    raise SystemExit(f"missing capabilities: {missing}")
PY
kv "control.HELLO" "PASS"

section "product_block"
kv "block.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetL4RuleSubject android.uid:$uid --es debugSetL4RuleFamily ipv4 --es debugSetL4RuleDestinationCidr $destination_cidr --ei debugSetL4RuleDestinationPortFirst $S58_TRAFFIC_PORT --ei debugSetL4RuleDestinationPortLast $S58_TRAFFIC_PORT --ei debugSetL4RuleIpProtocol 6 --es debugSetL4RuleDirection output --es debugSetL4RuleAction drop"
request_product_l4_rule "$uid" drop
wait_eval "$uid" DROP L4 "$rule_id" "policy_evaluate_block"
block_revision="$(json_field "${RESULT_DIR}/policy_evaluate_block.json" result.revision)"
kv "block.revision" "$block_revision"
query_control_json "status.before_first" "VPN_TUN.STATUS"

section "first_unknown_packet"
run_debug_probe "first"
wait_for_status_delta "${RESULT_DIR}/status.before_first.json" "status.after_first" "packetsSeen" 1
first_forward_delta="$(delta_value "${RESULT_DIR}/status.before_first.json" "${RESULT_DIR}/status.after_first.json" forwardedPackets)"
first_unknown_delta="$(delta_value "${RESULT_DIR}/status.before_first.json" "${RESULT_DIR}/status.after_first.json" uidUnknownFallbackPackets)"
first_drop_delta="$(delta_value "${RESULT_DIR}/status.before_first.json" "${RESULT_DIR}/status.after_first.json" droppedPackets)"
first_probe_result="$(probe_value "${RESULT_DIR}/first.probe.properties" result)"
kv "first.forwardedPacketsDelta" "$first_forward_delta"
kv "first.uidUnknownFallbackPacketsDelta" "$first_unknown_delta"
kv "first.droppedPacketsDelta" "$first_drop_delta"
kv "first.probe.result" "$first_probe_result"
[[ "$first_forward_delta" -ge 1 ]]
[[ "$first_unknown_delta" -ge 1 ]]
[[ "$first_drop_delta" -eq 0 ]]
[[ "$first_probe_result" == "tcp_connect_succeeded" ]]
kv "first.noRecognitionHold" "claimed"

section "late_attribution_then_drop"
attribution_args="$(attribution_apply_args "$uid" | compact_json)"
printf '%s\n' "$attribution_args" >"${RESULT_DIR}/attribution_apply.shell_args.json"
query_control_json "attribution_apply" "VPN_TUN.ATTRIBUTION.APPLY" "$attribution_args"
[[ "$(json_field "${RESULT_DIR}/attribution_apply.json" result.found)" == "True" ]]
[[ "$(json_field "${RESULT_DIR}/attribution_apply.json" result.updated)" == "True" ]]
kv "attribution.apply" "PASS"
query_control_json "status.after_attribution" "VPN_TUN.STATUS"
run_debug_probe "second"
wait_for_status_delta "${RESULT_DIR}/status.after_attribution.json" "status.after_second" "droppedPackets" 1
second_drop_delta="$(delta_value "${RESULT_DIR}/status.after_attribution.json" "${RESULT_DIR}/status.after_second.json" droppedPackets)"
resolution_delta="$(delta_value "${RESULT_DIR}/status.after_attribution.json" "${RESULT_DIR}/status.after_second.json" attributionResolutions)"
second_probe_result="$(probe_value "${RESULT_DIR}/second.probe.properties" result)"
activity_uid="$(activity_value "${RESULT_DIR}/status.after_second.json" lastLinuxUid)"
activity_stage="$(activity_value "${RESULT_DIR}/status.after_second.json" lastStage)"
activity_rule="$(activity_value "${RESULT_DIR}/status.after_second.json" lastRuleId)"
activity_revision="$(activity_value "${RESULT_DIR}/status.after_second.json" lastRevision)"
kv "second.droppedPacketsDelta" "$second_drop_delta"
kv "second.attributionResolutionsDelta" "$resolution_delta"
kv "second.probe.result" "$second_probe_result"
kv "second.policyDropActivity.uid" "$activity_uid"
kv "second.policyDropActivity.stage" "$activity_stage"
kv "second.policyDropActivity.rule" "$activity_rule"
kv "second.policyDropActivity.revision" "$activity_revision"
[[ "$second_drop_delta" -ge 1 ]]
[[ "$resolution_delta" -ge 1 ]]
[[ "$second_probe_result" == "tcp_connect_failed" ]]
[[ "$activity_uid" == "$uid" ]]
[[ "$activity_stage" == "L4" ]]
[[ "$activity_rule" == "$rule_id" ]]
[[ "$activity_revision" == "$block_revision" ]]
run_debug_l4_prefill "drop"
prefill_result="$(prefill_value "${RESULT_DIR}/drop.l4_prefill.properties" result)"
prefill_summary="$(prefill_value "${RESULT_DIR}/drop.l4_prefill.properties" summary)"
kv "drop.l4Prefill.result" "$prefill_result"
kv "drop.l4Prefill.summary" "$prefill_summary"
[[ "$prefill_result" == "available" ]]
[[ "$prefill_summary" == *"subject=android.uid:$uid"* ]]
[[ "$prefill_summary" == *"destinationCidr=$destination_cidr"* ]]
[[ "$prefill_summary" == *"destinationPort=$S58_TRAFFIC_PORT"* ]]
kv "drop.activityPrefill" "PASS"

section "product_restore"
kv "open.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetL4RuleSubject android.uid:$uid --es debugSetL4RuleFamily ipv4 --es debugSetL4RuleDestinationCidr $destination_cidr --ei debugSetL4RuleDestinationPortFirst $S58_TRAFFIC_PORT --ei debugSetL4RuleDestinationPortLast $S58_TRAFFIC_PORT --ei debugSetL4RuleIpProtocol 6 --es debugSetL4RuleDirection output --es debugSetL4RuleAction allow"
request_product_l4_rule "$uid" allow
wait_eval "$uid" PASS_NEXT None 0 "policy_evaluate_open"
open_revision="$(json_field "${RESULT_DIR}/policy_evaluate_open.json" result.revision)"
kv "open.revision" "$open_revision"
query_control_json "status.before_open_probe" "VPN_TUN.STATUS"
run_debug_probe "open"
wait_for_status_delta "${RESULT_DIR}/status.before_open_probe.json" "status.after_open_probe" "forwardedPackets" 1
open_forward_delta="$(delta_value "${RESULT_DIR}/status.before_open_probe.json" "${RESULT_DIR}/status.after_open_probe.json" forwardedPackets)"
open_drop_delta="$(delta_value "${RESULT_DIR}/status.before_open_probe.json" "${RESULT_DIR}/status.after_open_probe.json" droppedPackets)"
open_probe_result="$(probe_value "${RESULT_DIR}/open.probe.properties" result)"
allowed_uid="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastLinuxUid)"
allowed_source="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastSourceAddress)"
allowed_source_port="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastSourcePort)"
allowed_destination="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastDestinationAddress)"
allowed_destination_port="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastDestinationPort)"
allowed_protocol="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastIpProtocol)"
allowed_device_dir="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastDeviceDirection)"
allowed_flow_dir="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastFlowDirection)"
allowed_packets="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastPackets)"
allowed_bytes="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastBytes)"
allowed_revision="$(allowed_activity_value "${RESULT_DIR}/status.after_open_probe.json" lastPolicyRevision)"
if [[ "$allowed_device_dir" == "input" ]]; then
  allowed_remote="$allowed_source"
  allowed_port="$allowed_source_port"
else
  allowed_remote="$allowed_destination"
  allowed_port="$allowed_destination_port"
fi
kv "open.forwardedPacketsDelta" "$open_forward_delta"
kv "open.droppedPacketsDelta" "$open_drop_delta"
kv "open.probe.result" "$open_probe_result"
kv "open.allowedFlowActivity.uid" "$allowed_uid"
kv "open.allowedFlowActivity.remote" "$allowed_remote:$allowed_port"
kv "open.allowedFlowActivity.protocol" "$allowed_protocol"
kv "open.allowedFlowActivity.deviceDirection" "$allowed_device_dir"
kv "open.allowedFlowActivity.flowDirection" "$allowed_flow_dir"
kv "open.allowedFlowActivity.packets" "$allowed_packets"
kv "open.allowedFlowActivity.bytes" "$allowed_bytes"
kv "open.allowedFlowActivity.revision" "$allowed_revision"
[[ "$open_forward_delta" -ge 1 ]]
[[ "$open_drop_delta" -eq 0 ]]
[[ "$open_probe_result" == "tcp_connect_succeeded" ]]
[[ "$allowed_uid" == "$uid" ]]
[[ "$allowed_remote" == "$S58_TRAFFIC_HOST" ]]
[[ "$allowed_protocol" == "6" ]]
[[ "$allowed_port" == "$S58_TRAFFIC_PORT" ]]
[[ "$allowed_device_dir" == "input" || "$allowed_device_dir" == "output" ]]
[[ "$allowed_flow_dir" == "orig" || "$allowed_flow_dir" == "reply" ]]
[[ "$allowed_packets" =~ ^[0-9]+$ && "$allowed_packets" -gt 0 ]]
[[ "$allowed_bytes" =~ ^[0-9]+$ && "$allowed_bytes" -gt 0 ]]
[[ "$allowed_revision" == "$open_revision" ]]
kv "open.restoreAllowedFlowEntry" "PASS"

section "cleanup"
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >"${RESULT_DIR}/stop.intent.log" 2>&1
cleanup_ok=0
for _ in $(seq 1 30); do
  stopped="$(read_snapshot)"
  printf '%s\n' "$stopped" >"${RESULT_DIR}/snapshot.stopped"
  if grep -Fxq "state=stopped" <<<"$stopped" \
      && grep -Fxq "mayBeActive=false" <<<"$stopped"; then
    cleanup_ok=1
    kv "cleanup.result" "PASS"
    break
  fi
  if grep -Fxq "state=error" <<<"$stopped" \
      && grep -Fxq "pid=-1" <<<"$stopped" \
      && grep -Fxq "adapterReadiness=unavailable" <<<"$stopped" \
      && grep -Fxq "errorCode=runtime_ownership_unverified" <<<"$stopped"; then
    cleanup_ok=1
    kv "cleanup.result" "PASS_TERMINAL_ERROR"
    kv "cleanup.terminalError" "runtime_ownership_unverified"
    kv "cleanup.reason" "Runtime stopped with no native pid/adapter; ownership residue audit belongs to S69/S79, not S58 L4 workflow evidence"
    break
  fi
  sleep 1
done
if [[ "$cleanup_ok" != "1" ]]; then
  kv "cleanup.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.stopped" >&2
  exit 1
fi

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s58VpnProductWorkflowEvidence" "claimed"
