#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-56 product VPN attribution evidence matrix.
#
# This matrix uses the product RuntimeService VPN profile. It creates a
# deterministic unknown-UID VPN FlowEntry with a debug TCP probe using a fixed
# local source port, applies resolved UID attribution over vNext control, then
# proves the next packet with the same 5-tuple is re-evaluated by the resolved
# subject and L4-dropped without replaying the first verdict.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s56-vpn-attribution-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
S56_BUILD_APK="${S56_BUILD_APK:-1}"
S56_INSTALL_APK="${S56_INSTALL_APK:-1}"
S56_FORWARD_PORT="${S56_FORWARD_PORT:-60656}"
S56_CLEANUP_ON_EXIT="${S56_CLEANUP_ON_EXIT:-1}"
S56_TRAFFIC_HOST="${S56_TRAFFIC_HOST:-198.51.100.56}"
S56_TRAFFIC_PORT="${S56_TRAFFIC_PORT:-443}"
S56_SOURCE_PORT="${S56_SOURCE_PORT:-45656}"
S56_TRAFFIC_TIMEOUT_MILLIS="${S56_TRAFFIC_TIMEOUT_MILLIS:-700}"
STATE_PATH="files/runtime-state/snapshot.properties"
PROBE_RESULT_PATH="files/debug/traffic-probe.properties"
CONTROL_SOCKET="sucre-snort-control-vnext"

mkdir -p "$RESULT_DIR"
if [[ "${S56_MATRIX_LOGGING:-0}" != "1" ]]; then
  export S56_MATRIX_LOGGING=1
  exec > >(tee "${RESULT_DIR}/matrix.log") 2>&1
fi

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  if [[ "$S56_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
  adb_cmd forward --remove "tcp:${S56_FORWARD_PORT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

read_snapshot() {
  adb_cmd shell run-as "$PACKAGE" cat "$STATE_PATH" 2>/dev/null | tr -d '\r' || true
}

snapshot_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

wait_for_snapshot_field() {
  local key="$1"
  local expected="$2"
  local out_file="$3"
  local attempts="${4:-45}"
  local state=""
  for _ in $(seq 1 "$attempts"); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"$out_file"
    if grep -Fxq "${key}=${expected}" <<<"$state"; then
      printf '%s\n' "$state"
      return 0
    fi
    sleep 1
  done
  return 1
}

package_uid() {
  local line uid
  line="$(adb_cmd shell cmd package list packages -U "$PACKAGE" 2>/dev/null | tr -d '\r' | head -n 1)"
  uid="$(printf '%s\n' "$line" | sed -n 's/.* uid:\([0-9][0-9]*\).*/\1/p')"
  if [[ -n "$uid" ]]; then
    printf '%s\n' "$uid"
    return 0
  fi
  uid="$(adb_cmd shell run-as "$PACKAGE" id -u 2>/dev/null | tr -d '\r\n' || true)"
  [[ -n "$uid" ]] && printf '%s\n' "$uid"
}

query_control_json() {
  local name="$1"
  local command="$2"
  local args="{}"
  if [[ $# -ge 3 ]]; then
    args="$3"
  fi
  python3 - "$S56_FORWARD_PORT" "$RESULT_DIR" "$name" "$command" "$args" <<'PY'
import json
import pathlib
import socket
import sys

port = int(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])
name = sys.argv[3]
command = sys.argv[4]
raw_args = sys.argv[5]
(result_dir / f"{name}.args.json").write_text(raw_args + "\n")
args = json.loads(raw_args)

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

probe_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 } END { if (!found) exit 1 }' "$file"
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

compact_json() {
  python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), separators=(",", ":")))'
}

policy_apply_l4_drop() {
  local uid="$1"
  python3 - "$uid" "$S56_TRAFFIC_PORT" <<'PY'
import json
import sys

uid = int(sys.argv[1])
port = int(sys.argv[2])
payload = {
    "revision": 5601,
    "subjects": [{
        "linuxUid": uid,
        "networkGate": {},
        "l4Rules": [{
            "ruleId": 5601,
            "reasonId": 56,
            "priority": 0,
            "order": 0,
            "action": "drop",
            "match": {
                "family": "ipv4",
                "direction": "output",
                "ipProtocol": 6,
                "destinationPorts": {"first": port, "last": port},
            },
        }],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

attribution_apply_args() {
  local uid="$1"
  python3 - "$uid" "$S56_TRAFFIC_HOST" "$S56_TRAFFIC_PORT" "$S56_SOURCE_PORT" <<'PY'
import json
import sys

uid = int(sys.argv[1])
host = sys.argv[2]
port = int(sys.argv[3])
source_port = int(sys.argv[4])
payload = {
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
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

run_debug_probe() {
  local label="$1"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugTraffic true \
    --es debugTrafficHost "$S56_TRAFFIC_HOST" \
    --ei debugTrafficPort "$S56_TRAFFIC_PORT" \
    --ei debugTrafficSourcePort "$S56_SOURCE_PORT" \
    --ei debugTrafficTimeoutMillis "$S56_TRAFFIC_TIMEOUT_MILLIS" \
    >"${RESULT_DIR}/${label}.intent.log" 2>&1
  for _ in $(seq 1 30); do
    adb_cmd shell run-as "$PACKAGE" cat "$PROBE_RESULT_PATH" \
      2>/dev/null | tr -d '\r' >"${RESULT_DIR}/${label}.probe.properties" || true
    if grep -Fxq "sourcePort=${S56_SOURCE_PORT}" "${RESULT_DIR}/${label}.probe.properties"; then
      kv "${label}.probeResult" "${RESULT_DIR#${repo_root}/}/${label}.probe.properties"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_status_delta() {
  local before="$1"
  local out_name="$2"
  local key="$3"
  local min_delta="$4"
  local attempts="${5:-30}"
  local after="${RESULT_DIR}/${out_name}.json"
  for _ in $(seq 1 "$attempts"); do
    if ! query_control_json "$out_name" "VPN_TUN.STATUS" \
        >"${RESULT_DIR}/${out_name}.query.log" 2>&1; then
      kv "${out_name}.queryLog" "${RESULT_DIR#${repo_root}/}/${out_name}.query.log"
      return 1
    fi
    if [[ "$(delta_value "$before" "$after" "$key")" -ge "$min_delta" ]]; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-56-vpn-attribution"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "lateAttributionEvidence" "claimed"
kv "noRecognitionHoldEvidence" "claimed"
kv "completedVerdictRetroactiveModification" "not_claimed"
kv "multiUserIdentity" "not_claimed"

section "build_install"
if [[ "$S56_BUILD_APK" == "1" ]]; then
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
if [[ "$S56_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi
uid="$(package_uid || true)"
[[ -n "$uid" ]] || {
  kv "packageUid" "UNAVAILABLE"
  exit 1
}
kv "packageUid" "$uid"

section "start_vpn"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile vpn \
  >"${RESULT_DIR}/start.intent.log" 2>&1
state="$(wait_for_snapshot_field state running "${RESULT_DIR}/snapshot.running" 45)" || {
  kv "start.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.running" >&2
  exit 1
}
printf '%s\n' "$state" | grep -Fxq "profile=vpn"
printf '%s\n' "$state" | grep -Fxq "adapterReadiness=vpn-tun-hev"
kv "start.result" "PASS"
kv "snapshot.pid" "$(printf '%s\n' "$state" | snapshot_value pid)"

section "control"
adb_cmd forward "tcp:${S56_FORWARD_PORT}" "localabstract:${CONTROL_SOCKET}" \
  >"${RESULT_DIR}/adb-forward.log" 2>&1
query_control_json "hello" "HELLO"
python3 - "${RESULT_DIR}/hello.json" <<'PY'
import json
import sys

hello = json.load(open(sys.argv[1]))
capabilities = set(hello["result"]["capabilities"])
for required in ["packet-adapter-vpn-tun-hev", "packet-policy-control",
                 "vpn-tun-runtime-counters", "vpn-tun-attribution-control"]:
    if required not in capabilities:
        raise SystemExit(f"missing capability {required}")
PY
kv "control.HELLO" "PASS"

policy_args="$(policy_apply_l4_drop "$uid" | tail -n 1 | compact_json)"
printf '%s\n' "$policy_args" >"${RESULT_DIR}/policy_apply.shell_args.json"
query_control_json "policy_apply" "POLICY.APPLY" "$policy_args"
kv "policy.apply" "PASS"

query_control_json "status.before" "VPN_TUN.STATUS"

section "first_unknown_packet"
run_debug_probe "first"
wait_for_status_delta "${RESULT_DIR}/status.before.json" "status.after_first" "packetsSeen" 1
first_forward_delta="$(delta_value "${RESULT_DIR}/status.before.json" "${RESULT_DIR}/status.after_first.json" forwardedPackets)"
first_unknown_delta="$(delta_value "${RESULT_DIR}/status.before.json" "${RESULT_DIR}/status.after_first.json" uidUnknownFallbackPackets)"
first_drop_delta="$(delta_value "${RESULT_DIR}/status.before.json" "${RESULT_DIR}/status.after_first.json" droppedPackets)"
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

section "late_attribution"
attribution_args="$(attribution_apply_args "$uid" | tail -n 1 | compact_json)"
printf '%s\n' "$attribution_args" >"${RESULT_DIR}/attribution_apply.shell_args.json"
query_control_json "attribution_apply" "VPN_TUN.ATTRIBUTION.APPLY" "$attribution_args"
[[ "$(json_field "${RESULT_DIR}/attribution_apply.json" result.found)" == "True" ]]
[[ "$(json_field "${RESULT_DIR}/attribution_apply.json" result.updated)" == "True" ]]
kv "attribution.apply" "PASS"
kv "attribution.resolvedUid" "$uid"
query_control_json "status.after_attribution" "VPN_TUN.STATUS"
attribution_update_delta="$(delta_value "${RESULT_DIR}/status.after_first.json" "${RESULT_DIR}/status.after_attribution.json" attributionUpdates)"
retroactive_drop_delta="$(delta_value "${RESULT_DIR}/status.after_first.json" "${RESULT_DIR}/status.after_attribution.json" droppedPackets)"
kv "attribution.attributionUpdatesDelta" "$attribution_update_delta"
kv "attribution.retroactiveDroppedPacketsDelta" "$retroactive_drop_delta"
[[ "$attribution_update_delta" -ge 1 ]]
[[ "$retroactive_drop_delta" -eq 0 ]]
kv "attribution.completedVerdictNotRetroactive" "claimed"

section "second_unknown_packet_reevaluated"
run_debug_probe "second"
wait_for_status_delta "${RESULT_DIR}/status.after_attribution.json" "status.after_second" "droppedPackets" 1
second_drop_delta="$(delta_value "${RESULT_DIR}/status.after_attribution.json" "${RESULT_DIR}/status.after_second.json" droppedPackets)"
resolution_delta="$(delta_value "${RESULT_DIR}/status.after_attribution.json" "${RESULT_DIR}/status.after_second.json" attributionResolutions)"
kv "second.droppedPacketsDelta" "$second_drop_delta"
kv "second.attributionResolutionsDelta" "$resolution_delta"
[[ "$second_drop_delta" -ge 1 ]]
[[ "$resolution_delta" -ge 1 ]]
kv "matrix.s56LateAttributionEvidence" "claimed"

section "cleanup"
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >"${RESULT_DIR}/stop.intent.log" 2>&1
kv "cleanup.result" "PASS"
