#!/usr/bin/env bash
set -euo pipefail

SNORT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="$SNORT_ROOT/dev/adb"
source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-$PACKAGE/.DebugControlActivity}"
DEBUG_TRAFFIC_PROBE_RESULT_PATH="files/debug/traffic-probe.properties"
VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"
TRAFFIC_HOST="${TRAFFIC_HOST:-1.1.1.1}"
TRAFFIC_PORT="${TRAFFIC_PORT:-80}"
TRAFFIC_V6_HOST="${TRAFFIC_V6_HOST:-2606:4700:4700::1111}"
TRAFFIC_V6_PORT="${TRAFFIC_V6_PORT:-80}"
TRAFFIC_TIMEOUT_MILLIS="${TRAFFIC_TIMEOUT_MILLIS:-1500}"
REAL_TRAFFIC_NETWORK_CONTEXT="${REAL_TRAFFIC_NETWORK_CONTEXT:-1}"
MATRIX_RC=0

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>] [--ctl <path>]

Runs a focused SAKAMOTO-52 Root L4 product matrix:
  - create typed L4 rules through Android product debug seam
  - vNext L4PolicyMatcher evaluates explicit family/CIDR/ports/protocol/direction/context/action
  - fixed ordering is priority/order/ruleId
  - real Root TCP traffic is dropped and restored through product-authored L4 rules
  - IPv6 TCP, source CIDR, UDP, ICMP and other protocol vectors prove winner/default semantics

Requires an installed APK and an already running Root runtime exposing
localabstract:sucre-snort-control-vnext.
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
  remove_control_vnext_forward "$VNEXT_PORT"
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

json_path() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

obj = json.loads(sys.argv[2])
for part in sys.argv[1].split("."):
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
print(f"{label}.before={json.dumps(before, sort_keys=True, separators=(',', ':'))}")
print(f"{label}.after={json.dumps(after, sort_keys=True, separators=(',', ':'))}")
for key in ["packetsSeen", "acceptedPackets", "droppedPackets"]:
    print(f"{label}.{key}Delta={int(after.get(key, 0)) - int(before.get(key, 0))}")
activity = after.get("policyDropActivity", {})
for key in [
    "records", "capacity", "totalRecords", "evictedRecords", "lastLinuxUid",
    "lastUidKnown", "lastNetworkContext", "lastStage", "lastReasonId",
    "lastRuleId", "lastRevision",
]:
    print(f"{label}.policyDropActivity.{key}={activity.get(key)}")
PY
}

delta_value() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

before = json.loads(sys.argv[1])["result"]
after = json.loads(sys.argv[2])["result"]
print(int(after.get(sys.argv[3], 0)) - int(before.get(sys.argv[3], 0)))
PY
}

activity_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

doc = json.loads(sys.argv[1])["result"]
print(doc.get("policyDropActivity", {}).get(sys.argv[2], ""))
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

cidr_for_host() {
  local family="$1"
  local host="$2"
  if [[ "$family" == "ipv4" ]]; then
    printf '%s/32\n' "$host"
  else
    printf '%s/128\n' "$host"
  fi
}

request_product_l4_rule() {
  local uid="$1"
  local family="$2"
  local destination_cidr="$3"
  local ip_protocol="$4"
  local action="$5"
  local priority="$6"
  local order="$7"
  local destination_port="${8:-}"
  local source_cidr="${9:-}"
  local args=(
    shell am start -n "$ACTIVITY"
    --es debugSetL4RuleSubject "android.uid:${uid}"
    --es debugSetL4RuleFamily "$family"
    --es debugSetL4RuleDestinationCidr "$destination_cidr"
    --ei debugSetL4RuleIpProtocol "$ip_protocol"
    --es debugSetL4RuleDirection output
    --es debugSetL4RuleNetworkContext wifi
    --es debugSetL4RuleAction "$action"
    --ei debugSetL4RulePriority "$priority"
    --ei debugSetL4RuleOrder "$order"
  )
  if [[ -n "$source_cidr" ]]; then
    args+=(--es debugSetL4RuleSourceCidr "$source_cidr")
  fi
  if [[ -n "$destination_port" ]]; then
    args+=(--ei debugSetL4RuleDestinationPortFirst "$destination_port")
    args+=(--ei debugSetL4RuleDestinationPortLast "$destination_port")
  fi
  adb_cmd "${args[@]}" >/dev/null
}

policy_evaluate_l4() {
  local uid="$1"
  local context="$2"
  local family="$3"
  local destination_ip="$4"
  local ip_protocol="$5"
  local ports_available="$6"
  local destination_port="${7:-0}"
  python3 - "$uid" "$context" "$family" "$destination_ip" "$ip_protocol" \
    "$ports_available" "$destination_port" <<'PY'
import json
import sys

uid = int(sys.argv[1])
context = int(sys.argv[2])
family = sys.argv[3]
destination_ip = sys.argv[4]
ip_protocol = int(sys.argv[5])
ports_available = sys.argv[6] == "true"
destination_port = int(sys.argv[7])
payload = {
    "linuxUid": uid,
    "networkContext": context,
    "family": family,
    "direction": "output",
    "ipProtocol": ip_protocol,
    "sourceIp": "10.0.0.1" if family == "ipv4" else "2001:db8::1",
    "destinationIp": destination_ip,
    "portsAvailable": ports_available,
}
if ports_available:
    payload["sourcePort"] = 40000
    payload["destinationPort"] = destination_port
print(json.dumps(payload, separators=(",", ":")))
PY
}

assert_eval() {
  local label="$1"
  local response="$2"
  local expected_verdict="$3"
  local expected_stage="$4"
  local expected_rule="$5"
  local verdict stage rule
  verdict="$(json_path result.verdict "$response")"
  stage="$(json_path result.stage "$response")"
  rule="$(json_path result.ruleId "$response")"
  kv "$label.evaluateWinner" "$verdict/$stage/rule=$rule"
  if [[ "$verdict" == "$expected_verdict" && "$stage" == "$expected_stage" \
    && "$rule" == "$expected_rule" ]]; then
    kv "$label.evaluateResult" "PASS"
  else
    kv "$label.evaluateResult" "FAIL"
    MATRIX_RC=1
  fi
}

wait_eval() {
  local uid="$1"
  local family="$2"
  local destination_ip="$3"
  local ip_protocol="$4"
  local ports_available="$5"
  local destination_port="$6"
  local expected_verdict="$7"
  local expected_stage="$8"
  local expected_rule="$9"
  local response verdict stage rule
  for _ in $(seq 1 20); do
    response="$(ctl POLICY.EVALUATE "$(policy_evaluate_l4 "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT" "$family" "$destination_ip" "$ip_protocol" "$ports_available" "$destination_port")")"
    if ! printf '%s\n' "$response" | json_ok; then
      sleep 1
      continue
    fi
    verdict="$(json_path result.verdict "$response")"
    stage="$(json_path result.stage "$response")"
    rule="$(json_path result.ruleId "$response")"
    if [[ "$verdict" == "$expected_verdict" && "$stage" == "$expected_stage" \
      && "$rule" == "$expected_rule" ]]; then
      printf '%s\n' "$response"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$response"
  return 1
}

am_start_debug_traffic() {
  local host="$1"
  local port="$2"
  adb_cmd shell run-as "$PACKAGE" rm -f "$DEBUG_TRAFFIC_PROBE_RESULT_PATH" 2>/dev/null || true
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugTraffic true \
    --es debugTrafficHost "$host" \
    --ei debugTrafficPort "$port" \
    --ei debugTrafficTimeoutMillis "$TRAFFIC_TIMEOUT_MILLIS" >/dev/null
}

wait_debug_traffic_probe_result() {
  local expected_host="$1"
  for _ in $(seq 1 20); do
    if adb_cmd shell run-as "$PACKAGE" grep -Fxq "host=${expected_host}" \
        "$DEBUG_TRAFFIC_PROBE_RESULT_PATH" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

record_debug_traffic_probe_result() {
  local label="$1"
  adb_cmd shell run-as "$PACKAGE" cat "$DEBUG_TRAFFIC_PROBE_RESULT_PATH" 2>/dev/null \
    | tr -d '\r' \
    | sed "s/^/${label}.debugTraffic./" || true
}

debug_traffic_probe_value() {
  local key="$1"
  adb_cmd shell run-as "$PACKAGE" cat "$DEBUG_TRAFFIC_PROBE_RESULT_PATH" 2>/dev/null \
    | tr -d '\r' \
    | awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); found=1 } END { if (!found) exit 1 }'
}

section "preflight"
device_preflight || {
  echo "BLOCKED: device_preflight failed; need one rooted Android target"
  exit 77
}
setup_control_vnext_forward "$VNEXT_PORT"
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
ipv4_cidr="$(cidr_for_host ipv4 "$TRAFFIC_HOST")"
ipv6_cidr="$(cidr_for_host ipv6 "$TRAFFIC_V6_HOST")"
tcp_rule="$(stable_l4_rule_id "$uid" ipv4 6 10 0)"
tcp_v6_rule="$(stable_l4_rule_id "$uid" ipv6 6 10 1)"
source_cidr_rule="$(stable_l4_rule_id "$uid" ipv4 6 10 2)"
udp_rule="$(stable_l4_rule_id "$uid" ipv4 17 20 0)"
icmp_rule="$(stable_l4_rule_id "$uid" ipv4 1 30 0)"
other_rule="$(stable_l4_rule_id "$uid" ipv4 132 40 0)"
kv "matrix" "SAKAMOTO-52-root-l4-product-matrix"
kv "deviceId" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "uid.command" "./dev/adb shell cmd package list packages -U $PACKAGE"
kv "uid" "$uid"
kv "traffic" "$TRAFFIC_HOST:$TRAFFIC_PORT"
kv "trafficV6" "$TRAFFIC_V6_HOST:$TRAFFIC_V6_PORT"
kv "realTrafficNetworkContext" "$REAL_TRAFFIC_NETWORK_CONTEXT"
kv "priority/order/ruleId" "priority asc, explicit order asc, stable rule ID asc"

section "block_real_tcp_traffic"
kv "block.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetL4RuleSubject android.uid:$uid --es debugSetL4RuleFamily ipv4 --es debugSetL4RuleDestinationCidr $ipv4_cidr --ei debugSetL4RuleDestinationPortFirst $TRAFFIC_PORT --ei debugSetL4RuleDestinationPortLast $TRAFFIC_PORT --ei debugSetL4RuleIpProtocol 6 --es debugSetL4RuleDirection output --es debugSetL4RuleNetworkContext wifi --es debugSetL4RuleAction drop"
request_product_l4_rule "$uid" ipv4 "$ipv4_cidr" 6 drop 10 0 "$TRAFFIC_PORT" || true
eval_resp="$(wait_eval "$uid" ipv4 "$TRAFFIC_HOST" 6 true "$TRAFFIC_PORT" DROP L4 "$tcp_rule")"
printf 'block.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "block" "$eval_resp" DROP L4 "$tcp_rule"
block_revision="$(json_path result.revision "$eval_resp")"
before="$(ctl NFQUEUE.STATUS)"
am_start_debug_traffic "$TRAFFIC_HOST" "$TRAFFIC_PORT" || true
wait_debug_traffic_probe_result "$TRAFFIC_HOST" || true
record_debug_traffic_probe_result "block"
after="$(ctl NFQUEUE.STATUS)"
status_delta "$before" "$after" "block"
drop_delta="$(delta_value "$before" "$after" droppedPackets)"
probe_uid="$(debug_traffic_probe_value uid || true)"
probe_result="$(debug_traffic_probe_value result || true)"
activity_uid="$(activity_value "$after" lastLinuxUid)"
activity_stage="$(activity_value "$after" lastStage)"
activity_rule="$(activity_value "$after" lastRuleId)"
activity_revision="$(activity_value "$after" lastRevision)"
if [[ "$drop_delta" -gt 0 && "$probe_uid" == "$uid" \
  && "$probe_result" == "tcp_connect_failed" \
  && "$activity_uid" == "$uid" && "$activity_stage" == "L4" \
  && "$activity_rule" == "$tcp_rule" && "$activity_revision" == "$block_revision" ]]; then
  kv "block.result" "PASS"
else
  kv "block.result" "FAIL"
  kv "block.reason" "expected failed APK TCP traffic, NFQUEUE drop delta, and L4 policyDropActivity attribution"
  MATRIX_RC=1
fi

section "ipv6_tcp_vector"
request_product_l4_rule "$uid" ipv6 "$ipv6_cidr" 6 drop 10 1 "$TRAFFIC_V6_PORT" || true
eval_resp="$(wait_eval "$uid" ipv6 "$TRAFFIC_V6_HOST" 6 true "$TRAFFIC_V6_PORT" DROP L4 "$tcp_v6_rule")"
printf 'ipv6_tcp.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "ipv6_tcp" "$eval_resp" DROP L4 "$tcp_v6_rule"

section "source_cidr_vector"
kv "source_cidr.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetL4RuleSubject android.uid:$uid --es debugSetL4RuleFamily ipv4 --es debugSetL4RuleSourceCidr 10.0.0.0/8 --es debugSetL4RuleDestinationCidr 203.0.113.0/24 --ei debugSetL4RuleDestinationPortFirst 443 --ei debugSetL4RuleDestinationPortLast 443 --ei debugSetL4RuleIpProtocol 6 --es debugSetL4RuleDirection output --es debugSetL4RuleNetworkContext wifi --es debugSetL4RuleAction drop"
request_product_l4_rule "$uid" ipv4 "203.0.113.0/24" 6 drop 10 2 443 "10.0.0.0/8" || true
eval_resp="$(wait_eval "$uid" ipv4 203.0.113.9 6 true 443 DROP L4 "$source_cidr_rule")"
printf 'source_cidr.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "source_cidr" "$eval_resp" DROP L4 "$source_cidr_rule"

section "udp_vector"
request_product_l4_rule "$uid" ipv4 "$ipv4_cidr" 17 drop 20 0 "$TRAFFIC_PORT" || true
eval_resp="$(wait_eval "$uid" ipv4 "$TRAFFIC_HOST" 17 true "$TRAFFIC_PORT" DROP L4 "$udp_rule")"
printf 'udp.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "udp" "$eval_resp" DROP L4 "$udp_rule"

section "icmp_vector"
request_product_l4_rule "$uid" ipv4 "$ipv4_cidr" 1 drop 30 0 "" || true
eval_resp="$(wait_eval "$uid" ipv4 "$TRAFFIC_HOST" 1 false 0 DROP L4 "$icmp_rule")"
printf 'icmp.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "icmp" "$eval_resp" DROP L4 "$icmp_rule"

section "other_protocol_vector"
request_product_l4_rule "$uid" ipv4 "$ipv4_cidr" 132 drop 40 0 "" || true
eval_resp="$(wait_eval "$uid" ipv4 "$TRAFFIC_HOST" 132 false 0 DROP L4 "$other_rule")"
printf 'other.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "other" "$eval_resp" DROP L4 "$other_rule"
miss_resp="$(ctl POLICY.EVALUATE "$(policy_evaluate_l4 "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT" ipv4 198.51.100.44 132 false 0)")"
printf 'other.default.POLICY.EVALUATE=%s\n' "$miss_resp"
assert_eval "other.default" "$miss_resp" PASS_NEXT None 0

section "open_restore_tcp"
kv "open.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetL4RuleSubject android.uid:$uid --es debugSetL4RuleFamily ipv4 --es debugSetL4RuleDestinationCidr $ipv4_cidr --ei debugSetL4RuleDestinationPortFirst $TRAFFIC_PORT --ei debugSetL4RuleDestinationPortLast $TRAFFIC_PORT --ei debugSetL4RuleIpProtocol 6 --es debugSetL4RuleDirection output --es debugSetL4RuleNetworkContext wifi --es debugSetL4RuleAction allow"
request_product_l4_rule "$uid" ipv4 "$ipv4_cidr" 6 allow 10 0 "$TRAFFIC_PORT" || true
eval_resp="$(wait_eval "$uid" ipv4 "$TRAFFIC_HOST" 6 true "$TRAFFIC_PORT" PASS_NEXT None 0)"
printf 'open.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "open" "$eval_resp" PASS_NEXT None 0
before="$(ctl NFQUEUE.STATUS)"
am_start_debug_traffic "$TRAFFIC_HOST" "$TRAFFIC_PORT" || true
wait_debug_traffic_probe_result "$TRAFFIC_HOST" || true
record_debug_traffic_probe_result "open"
after="$(ctl NFQUEUE.STATUS)"
status_delta "$before" "$after" "open"
accepted_delta="$(delta_value "$before" "$after" acceptedPackets)"
drop_delta="$(delta_value "$before" "$after" droppedPackets)"
probe_uid="$(debug_traffic_probe_value uid || true)"
probe_result="$(debug_traffic_probe_value result || true)"
if [[ "$accepted_delta" -gt 0 && "$drop_delta" -eq 0 && "$probe_uid" == "$uid" \
  && "$probe_result" == "tcp_connect_succeeded" ]]; then
  kv "open.result" "PASS"
else
  kv "open.result" "FAIL"
  kv "open.reason" "expected product L4 allow to restore APK TCP connect without new policy drops"
  MATRIX_RC=1
fi

section "summary"
if [[ "$MATRIX_RC" -eq 0 ]]; then
  kv "matrix.s52Done" "not_claimed"
  kv "matrix.result" "PASS"
else
  kv "matrix.result" "FAIL"
fi
exit "$MATRIX_RC"
