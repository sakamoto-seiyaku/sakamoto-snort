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

Runs a focused SAKAMOTO-51 Root Network Gate product matrix:
  - package UID discovery through repo-local ./dev/adb
  - vNext Network Gate block -> real dual-stack APK traffic fails/drops
  - NFQUEUE.STATUS policyDropActivity attribution evidence
  - Network Gate open -> POLICY.EVALUATE PASS_NEXT and real traffic restores
  - Wi-Fi/Mobile/VPN context compile/evaluate matrix
  - Unknown Application subject evaluate
  - malformed apply failure preserves the previous runtime snapshot revision

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

policy_apply_gate() {
  local uid="$1"
  local revision="$2"
  local context="$3"
  local rule_id="$4"
  local reason_id="$5"
  python3 - "$uid" "$revision" "$context" "$rule_id" "$reason_id" <<'PY'
import json
import sys

uid, revision, context, rule_id, reason_id = map(int, sys.argv[1:])
payload = {
    "revision": revision,
    "subjects": [{
        "linuxUid": uid,
        "networkGate": {
            "rules": [{
                "networkContext": context,
                "ruleId": rule_id,
                "reasonId": reason_id,
            }],
        },
        "l4Rules": [],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

policy_apply_open() {
  local uid="$1"
  local revision="$2"
  python3 - "$uid" "$revision" <<'PY'
import json
import sys

uid, revision = map(int, sys.argv[1:])
payload = {
    "revision": revision,
    "subjects": [{
        "linuxUid": uid,
        "networkGate": {},
        "l4Rules": [],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

stable_gate_rule_id() {
  local uid="$1"
  local context="$2"
  python3 - "$uid" "$context" <<'PY'
import sys

uid, context = map(int, sys.argv[1:])
print((0x5100000000000000 | ((uid & 0xffffffff) << 8) | context))
PY
}

policy_apply_unknown_gate() {
  local revision="$1"
  local context="$2"
  local rule_id="$3"
  local reason_id="$4"
  python3 - "$revision" "$context" "$rule_id" "$reason_id" <<'PY'
import json
import sys

revision, context, rule_id, reason_id = map(int, sys.argv[1:])
payload = {
    "revision": revision,
    "subjects": [{
        "uidKnown": False,
        "networkGate": {
            "rules": [{
                "networkContext": context,
                "ruleId": rule_id,
                "reasonId": reason_id,
            }],
        },
        "l4Rules": [],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

policy_apply_duplicate_context() {
  local uid="$1"
  local revision="$2"
  python3 - "$uid" "$revision" <<'PY'
import json
import sys

uid, revision = map(int, sys.argv[1:])
payload = {
    "revision": revision,
    "subjects": [{
        "linuxUid": uid,
        "networkGate": {
            "rules": [
                {"networkContext": 0, "ruleId": 1, "reasonId": 1},
                {"networkContext": 0, "ruleId": 2, "reasonId": 2},
            ],
        },
        "l4Rules": [],
    }],
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

policy_evaluate() {
  local uid="$1"
  local context="$2"
  python3 - "$uid" "$context" "$TRAFFIC_PORT" <<'PY'
import json
import sys

uid, context, port = map(int, sys.argv[1:])
payload = {
    "linuxUid": uid,
    "networkContext": context,
    "family": "ipv4",
    "direction": "output",
    "ipProtocol": 6,
    "sourcePort": 40000,
    "destinationPort": port,
    "portsAvailable": True,
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

policy_evaluate_unknown() {
  local context="$1"
  python3 - "$context" "$TRAFFIC_PORT" <<'PY'
import json
import sys

context, port = map(int, sys.argv[1:])
payload = {
    "uidKnown": False,
    "networkContext": context,
    "family": "ipv4",
    "direction": "output",
    "ipProtocol": 6,
    "sourcePort": 40000,
    "destinationPort": port,
    "portsAvailable": True,
}
print(json.dumps(payload, separators=(",", ":")))
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

request_product_network_gate() {
  local uid="$1"
  local context_name="$2"
  local blocked="$3"
  adb_cmd shell am start -n "$ACTIVITY" \
    --es debugSetNetworkGateSubject "android.uid:${uid}" \
    --es debugSetNetworkGateContext "$context_name" \
    --ez debugSetNetworkGateBlocked "$blocked" >/dev/null
}

assert_eval() {
  local label="$1"
  local response="$2"
  local expected_verdict="$3"
  local expected_stage="$4"
  local expected_revision="$5"
  local expected_rule="$6"
  local verdict stage revision rule
  verdict="$(json_path result.verdict "$response")"
  stage="$(json_path result.stage "$response")"
  revision="$(json_path result.revision "$response")"
  rule="$(json_path result.ruleId "$response")"
  kv "$label.evaluateWinner" "$verdict/$stage/revision=$revision/rule=$rule"
  if [[ "$verdict" == "$expected_verdict" && "$stage" == "$expected_stage" \
    && "$revision" == "$expected_revision" && "$rule" == "$expected_rule" ]]; then
    kv "$label.evaluateResult" "PASS"
  else
    kv "$label.evaluateResult" "FAIL"
    MATRIX_RC=1
  fi
}

wait_eval_verdict() {
  local uid="$1"
  local context="$2"
  local expected_verdict="$3"
  local expected_stage="$4"
  local expected_rule="$5"
  local response verdict stage rule
  for _ in $(seq 1 20); do
    response="$(ctl POLICY.EVALUATE "$(policy_evaluate "$uid" "$context")")"
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
kv "matrix" "SAKAMOTO-51-root-network-gate-product-matrix"
kv "deviceId" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "uid.command" "./dev/adb shell cmd package list packages -U $PACKAGE"
kv "uid" "$uid"
kv "traffic" "$TRAFFIC_HOST:$TRAFFIC_PORT"
kv "trafficV6" "$TRAFFIC_V6_HOST:$TRAFFIC_V6_PORT"
kv "realTrafficNetworkContext" "$REAL_TRAFFIC_NETWORK_CONTEXT"
kv "controlPort" "$VNEXT_PORT"
kv "snortCtl" "$SNORT_CTL"

section "context_compile_matrix"
for entry in "wifi:1:510101:510101" "mobile:2:510102:510102" "vpn:3:510103:510103"; do
  IFS=: read -r name context rule reason <<<"$entry"
  apply_args="$(policy_apply_gate "$uid" "51${context}" "$context" "$rule" "$reason")"
  eval_args="$(policy_evaluate "$uid" "$context")"
  apply_resp="$(ctl POLICY.APPLY "$apply_args")"
  eval_resp="$(ctl POLICY.EVALUATE "$eval_args")"
  printf 'context_%s.POLICY.APPLY=%s\n' "$name" "$apply_resp"
  printf 'context_%s.POLICY.EVALUATE=%s\n' "$name" "$eval_resp"
  assert_eval "context_$name" "$eval_resp" "DROP" "NetworkGate" "51${context}" "$rule"
done

section "unknown_subject"
apply_args="$(policy_apply_unknown_gate 510200 0 510200 510200)"
eval_args="$(policy_evaluate_unknown 0)"
apply_resp="$(ctl POLICY.APPLY "$apply_args")"
eval_resp="$(ctl POLICY.EVALUATE "$eval_args")"
printf 'unknown_subject.POLICY.APPLY=%s\n' "$apply_resp"
printf 'unknown_subject.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "unknown_subject" "$eval_resp" "DROP" "NetworkGate" "510200" "510200"

section "block_real_traffic"
block_rule="$(stable_gate_rule_id "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT")"
eval_args="$(policy_evaluate "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT")"
kv "block.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetNetworkGateSubject android.uid:$uid --es debugSetNetworkGateContext wifi --ez debugSetNetworkGateBlocked true"
request_product_network_gate "$uid" wifi true || true
eval_resp="$(wait_eval_verdict "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT" "DROP" "NetworkGate" "$block_rule")"
block_revision="$(json_path result.revision "$eval_resp")"
printf 'block.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "block" "$eval_resp" "DROP" "NetworkGate" "$block_revision" "$block_rule"
before="$(ctl NFQUEUE.STATUS)"
kv "block.probe.command" "./dev/adb shell am start -n $ACTIVITY --ez debugTraffic true --es debugTrafficHost $TRAFFIC_HOST --ei debugTrafficPort $TRAFFIC_PORT"
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
  && "$activity_uid" == "$uid" && "$activity_stage" == "NetworkGate" \
  && "$activity_rule" == "$block_rule" && "$activity_revision" == "$block_revision" ]]; then
  kv "block.result" "PASS"
else
  kv "block.result" "FAIL"
  kv "block.reason" "expected failed APK traffic, NFQUEUE drop delta, and policyDropActivity attribution"
  MATRIX_RC=1
fi

section "block_real_ipv6_traffic"
before="$(ctl NFQUEUE.STATUS)"
kv "block_ipv6.probe.command" "./dev/adb shell am start -n $ACTIVITY --ez debugTraffic true --es debugTrafficHost $TRAFFIC_V6_HOST --ei debugTrafficPort $TRAFFIC_V6_PORT"
am_start_debug_traffic "$TRAFFIC_V6_HOST" "$TRAFFIC_V6_PORT" || true
wait_debug_traffic_probe_result "$TRAFFIC_V6_HOST" || true
record_debug_traffic_probe_result "block_ipv6"
after="$(ctl NFQUEUE.STATUS)"
status_delta "$before" "$after" "block_ipv6"
drop_delta="$(delta_value "$before" "$after" droppedPackets)"
probe_uid="$(debug_traffic_probe_value uid || true)"
probe_result="$(debug_traffic_probe_value result || true)"
activity_uid="$(activity_value "$after" lastLinuxUid)"
activity_context="$(activity_value "$after" lastNetworkContext)"
activity_stage="$(activity_value "$after" lastStage)"
activity_rule="$(activity_value "$after" lastRuleId)"
activity_revision="$(activity_value "$after" lastRevision)"
if [[ "$drop_delta" -gt 0 && "$probe_uid" == "$uid" \
  && "$probe_result" == "tcp_connect_failed" \
  && "$activity_uid" == "$uid" && "$activity_context" == "$REAL_TRAFFIC_NETWORK_CONTEXT" \
  && "$activity_stage" == "NetworkGate" \
  && "$activity_rule" == "$block_rule" && "$activity_revision" == "$block_revision" ]]; then
  kv "block_ipv6.result" "PASS"
else
  kv "block_ipv6.result" "FAIL"
  kv "block_ipv6.reason" "expected failed IPv6 APK traffic, NFQUEUE drop delta, and policyDropActivity attribution"
  MATRIX_RC=1
fi

section "apply_failure_preserves_snapshot"
bad_args="$(policy_apply_duplicate_context "$uid" 510301)"
bad_resp="$(ctl POLICY.APPLY "$bad_args" || true)"
eval_after_bad="$(ctl POLICY.EVALUATE "$eval_args")"
printf 'apply_failure.POLICY.APPLY=%s\n' "$bad_resp"
printf 'apply_failure.POLICY.EVALUATE_AFTER_BAD_APPLY=%s\n' "$eval_after_bad"
bad_ok="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("ok"))' <<<"$bad_resp" 2>/dev/null || true)"
revision_after_bad="$(json_path result.revision "$eval_after_bad")"
if [[ "$bad_ok" == "False" && "$revision_after_bad" == "$block_revision" ]]; then
  kv "apply_failure.result" "PASS"
else
  kv "apply_failure.result" "FAIL"
  kv "apply_failure.reason" "malformed duplicate-context apply must be rejected without replacing revision $block_revision"
  MATRIX_RC=1
fi

section "open_restore"
kv "open.product.command" "./dev/adb shell am start -n $ACTIVITY --es debugSetNetworkGateSubject android.uid:$uid --es debugSetNetworkGateContext wifi --ez debugSetNetworkGateBlocked false"
request_product_network_gate "$uid" wifi false || true
eval_args="$(policy_evaluate "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT")"
eval_resp="$(wait_eval_verdict "$uid" "$REAL_TRAFFIC_NETWORK_CONTEXT" "PASS_NEXT" "None" "0")"
printf 'open.POLICY.EVALUATE=%s\n' "$eval_resp"
assert_eval "open" "$eval_resp" "PASS_NEXT" "None" "0" "0"
before="$(ctl NFQUEUE.STATUS)"
kv "open.probe.command" "./dev/adb shell am start -n $ACTIVITY --ez debugTraffic true --es debugTrafficHost $TRAFFIC_HOST --ei debugTrafficPort $TRAFFIC_PORT"
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
  kv "open.reason" "expected open gate to restore APK TCP connect without new policy drops"
  MATRIX_RC=1
fi

section "open_restore_ipv6"
before="$(ctl NFQUEUE.STATUS)"
kv "open_ipv6.probe.command" "./dev/adb shell am start -n $ACTIVITY --ez debugTraffic true --es debugTrafficHost $TRAFFIC_V6_HOST --ei debugTrafficPort $TRAFFIC_V6_PORT"
am_start_debug_traffic "$TRAFFIC_V6_HOST" "$TRAFFIC_V6_PORT" || true
wait_debug_traffic_probe_result "$TRAFFIC_V6_HOST" || true
record_debug_traffic_probe_result "open_ipv6"
after="$(ctl NFQUEUE.STATUS)"
status_delta "$before" "$after" "open_ipv6"
accepted_delta="$(delta_value "$before" "$after" acceptedPackets)"
drop_delta="$(delta_value "$before" "$after" droppedPackets)"
probe_uid="$(debug_traffic_probe_value uid || true)"
probe_result="$(debug_traffic_probe_value result || true)"
if [[ "$accepted_delta" -gt 0 && "$drop_delta" -eq 0 && "$probe_uid" == "$uid" \
  && "$probe_result" == "tcp_connect_succeeded" ]]; then
  kv "open_ipv6.result" "PASS"
else
  kv "open_ipv6.result" "FAIL"
  kv "open_ipv6.reason" "expected open gate to restore APK IPv6 TCP connect without new policy drops"
  MATRIX_RC=1
fi

section "summary"
if [[ "$MATRIX_RC" -eq 0 ]]; then
  kv "matrix.s51Done" "not_claimed"
  kv "matrix.result" "PASS"
else
  kv "matrix.result" "FAIL"
fi
exit "$MATRIX_RC"
