#!/usr/bin/env bash
set -euo pipefail

SNORT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="$SNORT_ROOT/dev/adb"
source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-$PACKAGE/.DebugControlActivity}"
VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"
IPV6_OUTPUT_HOST="${IPV6_OUTPUT_HOST:-2606:4700:4700::1111}"
IPV6_OUTPUT_PORT="${IPV6_OUTPUT_PORT:-80}"
INPUT_LISTEN_PORT="${INPUT_LISTEN_PORT:-18080}"
INPUT_TIMEOUT_MILLIS="${INPUT_TIMEOUT_MILLIS:-5000}"
KEEP_FORWARD=0
RUN_RESTART=1

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>] [--ctl <path>] [--keep-forward] [--skip-restart]

Runs a minimal SAKAMOTO-68 Root/NFQUEUE device matrix slice:
  - real installed package UID evidence
  - IPv6 OUTPUT representative via APK debug traffic
  - IPv4 INPUT representative via APK one-shot listener + host peer connect
  - restart/no-residue checks

Environment overrides:
  PACKAGE, VNEXT_PORT, SNORT_CTL, IPV6_OUTPUT_HOST, IPV6_OUTPUT_PORT,
  INPUT_LISTEN_PORT, INPUT_TIMEOUT_MILLIS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --ctl)
      SNORT_CTL="$2"
      shift 2
      ;;
    --keep-forward)
      KEEP_FORWARD=1
      shift
      ;;
    --skip-restart)
      RUN_RESTART=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

section() {
  printf '\n## %s\n' "$1"
}

kv() {
  printf '%s=%s\n' "$1" "$2"
}

cleanup() {
  if [[ $KEEP_FORWARD -eq 0 ]]; then
    remove_control_vnext_forward "$VNEXT_PORT"
  fi
}
trap cleanup EXIT

find_snort_ctl() {
  if [[ -n "$SNORT_CTL" ]]; then
    [[ -x "$SNORT_CTL" ]] || {
      echo "BLOCKED: SNORT_CTL is not executable: $SNORT_CTL" >&2
      return 77
    }
    printf '%s\n' "$SNORT_CTL"
    return 0
  fi
  local candidates=(
    "$SNORT_ROOT/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/dev-relwithdebinfo/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/host-asan-clang/tests/host/sucre-snort-ctl"
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "BLOCKED: missing sucre-snort-ctl; build dev-debug target sucre-snort-ctl or pass --ctl" >&2
  return 77
}

ctl() {
  local cmd="$1"
  local args="${2:-}"
  if [[ -n "$args" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:$VNEXT_PORT" --compact "$cmd" "$args"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:$VNEXT_PORT" --compact "$cmd"
  fi
}

json_ok() {
  python3 -c 'import json,sys
try:
    ok = json.load(sys.stdin).get("ok") is True
except Exception:
    ok = False
sys.exit(0 if ok else 1)'
}

json_result() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path = sys.argv[1].split(".")
obj = json.loads(sys.argv[2])
for part in path:
    obj = obj[part]
print(obj)
PY
}

status_delta() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])["result"]
after = json.loads(sys.argv[2])["result"]
label = sys.argv[3]
keys = [
    "packetsSeen",
    "acceptedPackets",
    "droppedPackets",
    "parsePassThroughPackets",
    "capacityPassThroughPackets",
    "ownerFaultPassThroughPackets",
    "verdictSendFailures",
    "fragmentBufferedPackets",
    "fragmentReassembledPackets",
    "uidMetadataPresentPackets",
    "uidMetadataMissingPackets",
]
print(f"{label}.before={json.dumps(before, sort_keys=True, separators=(',', ':'))}")
print(f"{label}.after={json.dumps(after, sort_keys=True, separators=(',', ':'))}")
for key in keys:
    print(f"{label}.{key}Delta={int(after.get(key, 0)) - int(before.get(key, 0))}")
for key in [
    "lastObservedLinuxUid",
    "lastObservedNetworkContext",
    "lastObservedHook",
    "lastObservedInputInterfaceIndex",
    "lastObservedOutputInterfaceIndex",
    "lastObservedResult",
]:
    print(f"{label}.{key}={after.get(key)}")
PY
}

delta_value() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])["result"]
after = json.loads(sys.argv[2])["result"]
key = sys.argv[3]
print(int(after.get(key, 0)) - int(before.get(key, 0)))
PY
}

field_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

doc = json.loads(sys.argv[1])["result"]
print(doc.get(sys.argv[2], ""))
PY
}

policy_apply_l4_drop() {
  local uid="$1"
  local revision="$2"
  local family="$3"
  local direction="$4"
  local port="$5"
  local rule_id="$6"
  local reason_id="$7"
  python3 - "$uid" "$revision" "$family" "$direction" "$port" "$rule_id" "$reason_id" <<'PY'
import json
import sys

uid, revision, family, direction, port, rule_id, reason_id = sys.argv[1:]
payload = {
    "revision": int(revision),
    "subjects": [{
        "linuxUid": int(uid),
        "networkGate": {},
        "l4Rules": [{
            "ruleId": int(rule_id),
            "reasonId": int(reason_id),
            "priority": 10,
            "order": 0,
            "action": "drop",
            "match": {
                "family": family,
                "direction": direction,
                "ipProtocol": 6,
                "destinationPorts": {
                    "first": int(port),
                    "last": int(port),
                },
            },
        }],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

policy_evaluate() {
  local uid="$1"
  local family="$2"
  local direction="$3"
  local source_port="$4"
  local destination_port="$5"
  python3 - "$uid" "$family" "$direction" "$source_port" "$destination_port" <<'PY'
import json
import sys

uid, family, direction, source_port, destination_port = sys.argv[1:]
print(json.dumps({
    "linuxUid": int(uid),
    "networkContext": 0,
    "family": family,
    "direction": direction,
    "ipProtocol": 6,
    "sourcePort": int(source_port),
    "destinationPort": int(destination_port),
    "portsAvailable": True,
}, separators=(",", ":")))
PY
}

package_uid() {
  local line uid
  line="$(adb_cmd shell cmd package list packages -U "$PACKAGE" 2>/dev/null | tr -d '\r' | awk -v p="package:$PACKAGE " '$0 ~ "^package:" {print; exit}')"
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

am_start_debug_traffic() {
  local host="$1"
  local port="$2"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugTraffic true \
    --es debugTrafficHost "$host" \
    --ei debugTrafficPort "$port" \
    --ei debugTrafficTimeoutMillis 1500 >/dev/null
}

am_start_listener() {
  local port="$1"
  local timeout="$2"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugListen true \
    --ei debugListenPort "$port" \
    --ei debugListenTimeoutMillis "$timeout" >/dev/null
}

host_connect() {
  local host="$1"
  local port="$2"
  local timeout_seconds="$3"
  python3 - "$host" "$port" "$timeout_seconds" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])
sock = socket.create_connection((host, port), timeout=timeout)
sock.close()
PY
}

device_ipv4_for_host_peer() {
  adb_cmd shell "ip -o -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \\([0-9.][0-9.]*\\).*/\\1/p' | head -1" \
    | tr -d '\r\n'
}

check_no_residue() {
  local label="$1"
  local forwards procs ipt ip6t
  forwards="$(adb_cmd forward --list 2>/dev/null | tr -d '\r' | grep -F "localabstract:sucre-snort" || true)"
  procs="$(adb_su "pidof sucre-snort-dev libsucre_snortd.so sucre-snort-ndk 2>/dev/null || true" | tr -d '\r')"
  ipt="$(adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | tr -d '\r')"
  ip6t="$(adb_su "ip6tables -S 2>/dev/null | grep sucre-snort || true" | tr -d '\r')"

  kv "$label.forwardCheck.command" "./dev/adb forward --list | grep localabstract:sucre-snort"
  kv "$label.processCheck.command" "./dev/adb shell su 0 sh -c 'pidof sucre-snort-dev libsucre_snortd.so sucre-snort-ndk'"
  kv "$label.iptablesCheck.command" "./dev/adb shell su 0 sh -c 'iptables -S | grep sucre-snort'"
  kv "$label.ip6tablesCheck.command" "./dev/adb shell su 0 sh -c 'ip6tables -S | grep sucre-snort'"
  if [[ -z "$forwards" && -z "$procs" && -z "$ipt" && -z "$ip6t" ]]; then
    kv "$label.result" "PASS"
  else
    kv "$label.result" "FAIL"
    [[ -n "$forwards" ]] && kv "$label.forwardResidue" "$forwards"
    [[ -n "$procs" ]] && kv "$label.processResidue" "$procs"
    [[ -n "$ipt" ]] && kv "$label.iptablesResidue" "$ipt"
    [[ -n "$ip6t" ]] && kv "$label.ip6tablesResidue" "$ip6t"
  fi
}

wait_no_daemon_process() {
  local pids=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pids="$(adb_su "pidof sucre-snort-dev libsucre_snortd.so sucre-snort-ndk 2>/dev/null || true" | tr -d '\r')"
    if [[ -z "$pids" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

stop_root_daemon_for_cleanup() {
  local label="$1"
  kv "$label.quit.command" "$SNORT_CTL --tcp 127.0.0.1:$VNEXT_PORT --compact QUIT"
  ctl QUIT >/dev/null 2>&1 || true
  wait_no_daemon_process || {
    kv "$label.kill.command" "./dev/adb shell su 0 sh -c 'killall sucre-snort-dev libsucre_snortd.so sucre-snort-ndk'"
    adb_su "killall sucre-snort-dev libsucre_snortd.so sucre-snort-ndk 2>/dev/null || true" >/dev/null
    wait_no_daemon_process || true
  }
  remove_control_vnext_forward "$VNEXT_PORT"
}

redeploy_root_daemon() {
  local serial
  serial="$(adb_target_desc)"
  kv "restart.redeploy.command" "CONTROL_FORWARD_PORT=$VNEXT_PORT bash dev/dev-deploy.sh --serial $serial --no-clear-log"
  CONTROL_FORWARD_PORT="$VNEXT_PORT" bash "$SNORT_ROOT/dev/dev-deploy.sh" \
    --serial "$serial" --no-clear-log >/dev/null
}

section "preflight"
device_preflight || {
  echo "BLOCKED: device_preflight failed; need one rooted Android target"
  exit 77
}
if ! check_control_vnext_forward "$VNEXT_PORT"; then
  setup_control_vnext_forward "$VNEXT_PORT"
fi
SNORT_CTL="$(find_snort_ctl)"
export SNORT_CTL
hello="$(ctl HELLO || true)"
printf 'HELLO=%s\n' "$hello"
if ! printf '%s\n' "$hello" | json_ok; then
  echo "BLOCKED: HELLO failed via port $VNEXT_PORT"
  exit 77
fi
uid="$(package_uid || true)"
if [[ ! "$uid" =~ ^[0-9]+$ ]]; then
  echo "BLOCKED: unable to read installed package UID for $PACKAGE"
  exit 77
fi
kv "deviceId" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "uid.command" "./dev/adb shell cmd package list packages -U $PACKAGE"
kv "uid" "$uid"
kv "buildFingerprint" "$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
kv "controlPort" "$VNEXT_PORT"
kv "snortCtl" "$SNORT_CTL"

section "ipv6_output"
kv "ipv6_output.routeCheck.command" "./dev/adb shell ip -6 route get $IPV6_OUTPUT_HOST"
ipv6_route="$(adb_cmd shell ip -6 route get "$IPV6_OUTPUT_HOST" 2>&1 | tr -d '\r' || true)"
kv "ipv6_output.routeCheck.output" "$ipv6_route"
if [[ "$ipv6_route" == *"unreachable"* || "$ipv6_route" == *"Network is unreachable"* \
  || "$ipv6_route" != *" dev "* ]]; then
  kv "ipv6_output.result" "BLOCKED"
  kv "ipv6_output.reason" "device has no usable IPv6 route to $IPV6_OUTPUT_HOST"
else
  revision=680201
  apply_args="$(policy_apply_l4_drop "$uid" "$revision" ipv6 output "$IPV6_OUTPUT_PORT" 680201 680201)"
  eval_args="$(policy_evaluate "$uid" ipv6 output 40000 "$IPV6_OUTPUT_PORT")"
  kv "ipv6_output.POLICY.APPLY.command" "$SNORT_CTL --tcp 127.0.0.1:$VNEXT_PORT --compact POLICY.APPLY '$apply_args'"
  apply_resp="$(ctl POLICY.APPLY "$apply_args")"
  printf 'ipv6_output.POLICY.APPLY=%s\n' "$apply_resp"
  kv "ipv6_output.POLICY.EVALUATE.command" "$SNORT_CTL --tcp 127.0.0.1:$VNEXT_PORT --compact POLICY.EVALUATE '$eval_args'"
  eval_resp="$(ctl POLICY.EVALUATE "$eval_args")"
  printf 'ipv6_output.POLICY.EVALUATE=%s\n' "$eval_resp"
  before="$(ctl NFQUEUE.STATUS)"
  kv "ipv6_output.probe.command" "./dev/adb shell am start -n $ACTIVITY --ez debugTraffic true --es debugTrafficHost $IPV6_OUTPUT_HOST --ei debugTrafficPort $IPV6_OUTPUT_PORT --ei debugTrafficTimeoutMillis 1500"
  am_start_debug_traffic "$IPV6_OUTPUT_HOST" "$IPV6_OUTPUT_PORT" || true
  sleep 2
  after="$(ctl NFQUEUE.STATUS)"
  status_delta "$before" "$after" "ipv6_output"
  drop_delta="$(delta_value "$before" "$after" droppedPackets)"
  last_uid="$(field_value "$after" lastObservedLinuxUid)"
  last_result="$(field_value "$after" lastObservedResult)"
  eval_verdict="$(json_result result.verdict "$eval_resp")"
  eval_stage="$(json_result result.stage "$eval_resp")"
  eval_revision="$(json_result result.revision "$eval_resp")"
  kv "ipv6_output.evaluateWinner" "$eval_verdict/$eval_stage/revision=$eval_revision"
  if [[ "$eval_verdict" == "DROP" && "$drop_delta" -gt 0 && "$last_uid" == "$uid" && "$last_result" == "FlowDropped" ]]; then
    kv "ipv6_output.result" "PASS"
  else
    kv "ipv6_output.result" "FAIL"
    kv "ipv6_output.reason" "expected DROP evaluation plus dropped NFQUEUE delta for uid=$uid"
  fi
fi

section "input_ipv4"
device_ip="$(device_ipv4_for_host_peer)"
kv "input_ipv4.deviceIp.command" "./dev/adb shell ip -o -4 route get 1.1.1.1"
kv "input_ipv4.deviceIp" "${device_ip:-}"
if [[ -z "$device_ip" ]]; then
  kv "input_ipv4.result" "BLOCKED"
  kv "input_ipv4.reason" "unable to discover device IPv4 address for host peer traffic"
else
  revision=680301
  apply_args="$(policy_apply_l4_drop "$uid" "$revision" ipv4 input "$INPUT_LISTEN_PORT" 680301 680301)"
  eval_args="$(policy_evaluate "$uid" ipv4 input 40001 "$INPUT_LISTEN_PORT")"
  kv "input_ipv4.POLICY.APPLY.command" "$SNORT_CTL --tcp 127.0.0.1:$VNEXT_PORT --compact POLICY.APPLY '$apply_args'"
  apply_resp="$(ctl POLICY.APPLY "$apply_args")"
  printf 'input_ipv4.POLICY.APPLY=%s\n' "$apply_resp"
  kv "input_ipv4.POLICY.EVALUATE.command" "$SNORT_CTL --tcp 127.0.0.1:$VNEXT_PORT --compact POLICY.EVALUATE '$eval_args'"
  eval_resp="$(ctl POLICY.EVALUATE "$eval_args")"
  printf 'input_ipv4.POLICY.EVALUATE=%s\n' "$eval_resp"
  before="$(ctl NFQUEUE.STATUS)"
  kv "input_ipv4.listener.command" "./dev/adb shell am start -n $ACTIVITY --ez debugListen true --ei debugListenPort $INPUT_LISTEN_PORT --ei debugListenTimeoutMillis $INPUT_TIMEOUT_MILLIS"
  am_start_listener "$INPUT_LISTEN_PORT" "$INPUT_TIMEOUT_MILLIS" || true
  sleep 1
  kv "input_ipv4.peer.command" "python3 socket.create_connection(($device_ip,$INPUT_LISTEN_PORT), timeout=3)"
  peer_output="$(host_connect "$device_ip" "$INPUT_LISTEN_PORT" 3 2>&1 || true)"
  [[ -n "$peer_output" ]] && kv "input_ipv4.peer.output" "$peer_output"
  sleep 1
  after="$(ctl NFQUEUE.STATUS)"
  status_delta "$before" "$after" "input_ipv4"
  drop_delta="$(delta_value "$before" "$after" droppedPackets)"
  packet_delta="$(delta_value "$before" "$after" packetsSeen)"
  last_uid="$(field_value "$after" lastObservedLinuxUid)"
  last_result="$(field_value "$after" lastObservedResult)"
  last_hook="$(field_value "$after" lastObservedHook)"
  eval_verdict="$(json_result result.verdict "$eval_resp")"
  eval_stage="$(json_result result.stage "$eval_resp")"
  eval_revision="$(json_result result.revision "$eval_resp")"
  kv "input_ipv4.evaluateWinner" "$eval_verdict/$eval_stage/revision=$eval_revision"
  if [[ "$eval_verdict" == "DROP" && "$drop_delta" -gt 0 && "$last_uid" == "$uid" && "$last_result" == "FlowDropped" ]]; then
    kv "input_ipv4.result" "PASS"
    kv "input_ipv4.hookObserved" "$last_hook"
  elif [[ "$packet_delta" -gt 0 && "$last_uid" != "$uid" ]]; then
    kv "input_ipv4.result" "INVALID"
    kv "input_ipv4.reason" "NFQUEUE observed packets but NFQA_UID/route did not attribute INPUT to package uid=$uid"
    kv "input_ipv4.hookObserved" "$last_hook"
  else
    kv "input_ipv4.result" "FAIL"
    kv "input_ipv4.reason" "expected INPUT packet and dropped NFQUEUE delta for uid=$uid"
  fi
fi

if [[ $RUN_RESTART -eq 1 ]]; then
  section "restart_no_residue"
  stop_root_daemon_for_cleanup "restart.stop"
  check_no_residue "restart.afterStop"
  redeploy_root_daemon
  setup_control_vnext_forward "$VNEXT_PORT"
  hello2="$(ctl HELLO || true)"
  printf 'restart.HELLO=%s\n' "$hello2"
  if printf '%s\n' "$hello2" | json_ok; then
    kv "restart.helloResult" "PASS"
  else
    kv "restart.helloResult" "FAIL"
  fi
  before="$(ctl NFQUEUE.STATUS)"
  apply_args="$(policy_apply_l4_drop "$uid" 680401 ipv4 output 80 680401 680401)"
  eval_args="$(policy_evaluate "$uid" ipv4 output 40000 80)"
  apply_resp="$(ctl POLICY.APPLY "$apply_args")"
  eval_resp="$(ctl POLICY.EVALUATE "$eval_args")"
  printf 'restart.POLICY.APPLY=%s\n' "$apply_resp"
  printf 'restart.POLICY.EVALUATE=%s\n' "$eval_resp"
  am_start_debug_traffic 1.1.1.1 80 || true
  sleep 2
  after="$(ctl NFQUEUE.STATUS)"
  status_delta "$before" "$after" "restart.probe"
  stop_root_daemon_for_cleanup "restart.finalStop"
  check_no_residue "restart.finalCleanup"
fi
