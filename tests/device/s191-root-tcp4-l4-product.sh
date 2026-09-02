#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-191 Root IPv4 TCP stateless L4 real-device acceptance.
#
# PASS means the installed debug APK on the controlled Pixel 6a starts Root
# Product Core, publishes one Root IPv4/TCP L4 rule through ProductBackend ->
# Rust Product Core -> VAPI -> VPP, proves matching controlled TCP is dropped,
# proves a different TCP port is PASS_NEXT/no-match, applies a successor allow
# rule for the same tuple, proves traffic restores, reconciles that rule across
# restart, then stops without active residue.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S191_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${PACKAGE}/.DebugControlActivity"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s191-root-tcp4-l4}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s191-device-run.lock"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly S188_STATUS_PATH="files/product-state/s188-empty-policy-snapshot.properties"
readonly S191_STATUS_PATH="files/product-state/s191-root-tcp4-l4.properties"
readonly L4_STORE_PATH="files/product-policy/policy-bundle.properties"
readonly LEGACY_L4_STORE_PATH="files/product-policy/l4-intent.properties"
readonly TRAFFIC_PROBE_PATH="files/debug/traffic-probe.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly S191_WAIT_ATTEMPTS="${S191_WAIT_ATTEMPTS:-240}"
readonly S191_ADB_COMMAND_TIMEOUT_SECONDS="${S191_ADB_COMMAND_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s191-root-tcp4-l4-product.sh --run --host <controlled-lan-ipv4>

Required:
  --run
  --host / S191_CONTROLLED_LAN_HOST

Optional:
  --serial 28201JEGR0XPAJ
  --port / S191_TCP4_PORT             default 19191
  --timeout-ms / S191_TIMEOUT_MILLIS  default 5000

Before running, install the debug APK, grant POST_NOTIFICATIONS, and grant the
app Superuser in KernelSU Manager. ADB shell root alone is not accepted as
Product root authorization.

Required final evidence:
  installed_app_uid_complete=true
  baseline_traffic=tcp_echo_matched
  l4_drop=true
  blocked_traffic=tcp_connect_failed
  policy_drop_recorded=true
  physical_nfqueue_completion=true
  no_match_pass_next=true
  l4_allow=true
  allow_restore_traffic=tcp_echo_matched
  restart_after_allow_same_revision=true
EOF
}

serial="$S191_SERIAL"
run=0
controlled_host="${S191_CONTROLLED_LAN_HOST:-}"
port="${S191_TCP4_PORT:-19191}"
timeout_ms="${S191_TIMEOUT_MILLIS:-5000}"
run_lock_acquired=0
server_pid=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --run)
      run=1
      shift
      ;;
    --host)
      controlled_host="${2:-}"
      shift 2
      ;;
    --port)
      port="${2:-}"
      shift 2
      ;;
    --timeout-ms)
      timeout_ms="${2:-}"
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

if [[ "$serial" != "$S191_SERIAL" ]]; then
  echo "SAKAMOTO-191 only accepts controlled Pixel 6a serial $S191_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S191_CONTROLLED_LAN_HOST" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Controlled LAN host must be an IPv4 literal: $controlled_host" >&2
  exit 2
fi
if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65534 )); then
  echo "invalid TCP4 port: $port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi
nomatch_port=$((port + 1))
if (( nomatch_port > 65535 )); then
  nomatch_port=$((port - 1))
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-191 FAIL: $1" >&2
  exit 1
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if timeout "$S191_ADB_COMMAND_TIMEOUT_SECONDS" "$ADB" "$@"; then
      return 0
    fi
    rc=$?
    sleep 1
  done
  return "$rc"
}

adb_target() {
  adb_raw -s "$serial" "$@"
}

adb_devices_contains_serial() {
  local output="$RESULT_DIR/adb-devices.txt"
  local attempt
  for attempt in 1 2 3 4 5; do
    if adb_raw devices > "$output" 2>"$RESULT_DIR/adb-devices.stderr"; then
      if tr -d '\r' < "$output" \
          | awk 'NR > 1 && $1 == serial && $2 == "device" { found = 1 } END { exit found ? 0 : 1 }' serial="$serial"; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

read_device_model() {
  local output="$1"
  local tmp="${output}.tmp"
  local attempt
  local model
  for attempt in 1 2 3 4 5; do
    if adb_target shell getprop ro.product.model > "$tmp" 2>"$RESULT_DIR/device-model.stderr"; then
      model="$(tr -d '\r\n' < "$tmp")"
      if [[ -n "$model" ]]; then
        printf '%s\n' "$model" > "$output"
        rm -f "$tmp"
        return 0
      fi
    fi
    sleep 1
  done
  rm -f "$tmp"
  return 1
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "$RESULT_DIR/am-start.log" 2>&1
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

clear_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" rm -f "$relative" >/dev/null 2>&1 || true
}

cleanup_product_state_for_acceptance() {
  clear_app_file "$PRODUCT_STATE_PATH"
  clear_app_file "$PRODUCT_TRANSACTIONS_PATH"
  clear_app_file "$S188_STATUS_PATH"
  clear_app_file "$S191_STATUS_PATH"
  clear_app_file "$L4_STORE_PATH"
  clear_app_file "$LEGACY_L4_STORE_PATH"
  clear_app_file "$TRAFFIC_PROBE_PATH"
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$run_lock_acquired" == 1 ]]; then
    start_activity --ez runtimeStop true >/dev/null 2>&1 || true
    rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

acquire_run_lock() {
  mkdir -p "$RESULTS_ROOT"
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "$RUN_LOCK_DIR/pid"
    kv device_run_lock_acquired true
    return
  fi
  local lock_pid=""
  if [[ -f "$RUN_LOCK_DIR/pid" ]]; then
    lock_pid="$(tr -cd '0-9' < "$RUN_LOCK_DIR/pid" 2>/dev/null || true)"
  fi
  if [[ -n "$lock_pid" && "$lock_pid" != "$$" ]] \
      && kill -0 "$lock_pid" 2>/dev/null; then
    local lock_args=""
    lock_args="$(ps -p "$lock_pid" -o args= 2>/dev/null || true)"
    if [[ "$lock_args" == *"s191-root"* ]]; then
      fail_closed "another S191 runner is active: pid=$lock_pid"
    fi
    kv stale_run_lock_pid_reused "$lock_pid"
  fi
  rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
  rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "$RUN_LOCK_DIR/pid"
    kv device_run_lock_acquired true
    kv stale_run_lock_recovered true
    return
  fi
  fail_closed "could not acquire S191 device run lock"
}

property_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' "$file"
}

number_property() {
  local file="$1"
  local key="$2"
  local value
  value="$(property_value "$file" "$key")"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    fail_closed "${key} is not numeric in ${file}"
  fi
  printf '%s\n' "$value"
}

truthy_property() {
  local file="$1"
  local key="$2"
  local value
  value="$(property_value "$file" "$key")"
  [[ "$value" == "true" || "$value" == "1" ]]
}

wait_for_state() {
  local expected="$1"
  local output="$RESULT_DIR/state-${expected}.properties"
  local attempt
  for attempt in $(seq 1 "$S191_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fq "state=${expected}" "$output"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

validate_runtime_state_file() {
  local file="$1"
  python3 - "$file" <<'PY'
import pathlib
import sys

props = {}
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

def need(key, expected=None):
    actual = props.get(key, "")
    if expected is not None and actual != expected:
        raise SystemExit(f"{key}={actual!r}, expected {expected!r}")
    if expected is None and actual == "":
        raise SystemExit(f"{key} is empty")
    return actual

need("state", "running")
need("profile", "root")
need("adapterReadiness", "root-nfqueue")
need("coreHealth", "ok")
need("errorCode", "")
need("mayBeActive", "true")
generation = int(need("generation"))
if generation <= 0:
    raise SystemExit("generation is not positive")
print(f"generation={generation}")
print("adapterReadiness=root-nfqueue")
PY
}

wait_for_running_root() {
  local output="$RESULT_DIR/root.runtime-state.properties"
  local values="$RESULT_DIR/root.runtime-state.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S191_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if validate_runtime_state_file "$output" > "$values" 2>"$RESULT_DIR/root.runtime-state.stderr"; then
      while IFS= read -r line; do
        kv "root.runtime.${line%%=*}" "${line#*=}"
      done < "$values"
      return 0
    fi
    if grep -Fq 'errorCode=root_authorization_required' "$output"; then
      fail_closed "Root start requires KernelSU Superuser grant for $PACKAGE"
    fi
    if grep -Fq 'errorCode=notification_permission_required' "$output"; then
      fail_closed "Root start requires Android notification permission"
    fi
    sleep 0.5
  done
  fail_closed "Root Product Core did not reach running/root/root-nfqueue"
}

wait_for_s188_empty() {
  local output="$RESULT_DIR/baseline.s188.properties"
  local attempt
  for attempt in $(seq 1 "$S191_WAIT_ATTEMPTS"); do
    read_app_file "$S188_STATUS_PATH" > "$output"
    if grep -Fq 'schema=s188-empty-policy-snapshot/v1' "$output" \
        && truthy_property "$output" "empty_default_pass" \
        && truthy_property "$output" "worker_revision_match" \
        && truthy_property "$output" "artifact_match"; then
      kv baseline_empty_revision "$(property_value "$output" active_revision)"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "empty default-pass baseline did not publish valid S188 evidence"
}

validate_s191_status_file() {
  local file="$1"
  local expected_stage="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_action="$5"
  local expected_port="$6"
  local min_revision="$7"
  local require_match="$8"
  local require_drop="$9"
  local require_no_match="${10}"
  python3 - "$file" "$expected_stage" "$expected_uid" "$expected_context" \
    "$expected_action" "$expected_port" "$min_revision" "$require_match" \
    "$require_drop" "$require_no_match" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_stage = sys.argv[2]
expected_uid = int(sys.argv[3])
expected_context = int(sys.argv[4])
expected_action_name = sys.argv[5]
expected_port = int(sys.argv[6])
min_revision = int(sys.argv[7])
require_match = sys.argv[8].lower() == "true"
require_drop = sys.argv[9].lower() == "true"
require_no_match = sys.argv[10].lower() == "true"
expected_action = 2 if expected_action_name == "drop" else 1
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

def need(key, expected=None):
    actual = props.get(key, "")
    if expected is not None and actual != expected:
        raise SystemExit(f"{key}={actual!r}, expected {expected!r}")
    if expected is None and actual == "":
        raise SystemExit(f"{key} is empty")
    return actual

def number(key):
    try:
        return int(need(key))
    except ValueError as error:
        raise SystemExit(f"{key} is not numeric") from error

def truthy(key):
    actual = need(key).lower()
    if actual not in ("1", "true"):
        raise SystemExit(f"{key}={actual!r}, expected true")

def falsey(key):
    actual = need(key).lower()
    if actual not in ("0", "false"):
        raise SystemExit(f"{key}={actual!r}, expected false")

need("schema", "s191-root-tcp4-l4/v1")
actual_stage = need("stage")
if expected_stage in ("-", "l4_apply"):
    if actual_stage not in ("running", "l4_apply"):
        raise SystemExit(f'actual_stage not in ("running", "l4_apply"): {actual_stage}')
else:
    need("stage", expected_stage)
need("profile", "root")
need("state", "running")
need("errorCode", "")
requested = number("requested_revision")
active = number("active_revision")
if requested <= 0 or active <= 0 or requested != active:
    raise SystemExit("requested/active revision mismatch")
if active <= min_revision:
    raise SystemExit(f"active_revision={active}, expected > {min_revision}")
truthy("revision_match")
truthy("generation_match")
truthy("worker_revision_match")
truthy("artifact_match")
truthy("policy_default_pass")
truthy("l4_snapshot")
falsey("policy_snapshot_empty")
falsey("ui_policy_authority")
falsey("vpp_policy_authority")
truthy("rust_product_store_single_writer")
truthy("gate_before_l4")
truthy("stateless_l4_matcher")
truthy("root_adapter_completion_separate")
truthy("adapter_completion_separate")
if need("rust_product_store") != "product-policy/policy-bundle.properties":
    raise SystemExit("complete policy bundle is not authoritative")
if number("gate_claim_count") != 0:
    raise SystemExit("gate_claim_count must be zero")
if number("l4_rule_count") != 1:
    raise SystemExit("l4_rule_count must be one")
truthy("uid_complete")
if number("l4_subject_uid") != expected_uid:
    raise SystemExit("l4_subject_uid mismatch")
if number("l4_network_context") != expected_context:
    raise SystemExit("l4_network_context mismatch")
need("l4_family", "4")
need("l4_protocol", "6")
need("l4_ip_family", "4")
need("l4_ip_protocol", "6")
need("l4_direction", "OUTPUT")
need("l4_direction_code", "3")
need("l4_action", expected_action_name)
if number("l4_action_code") != expected_action:
    raise SystemExit("l4_action_code mismatch")
need("l4_source_cidr", "0.0.0.0/0")
if not need("l4_destination_cidr").endswith("/32"):
    raise SystemExit("destination CIDR must be an IPv4 host route")
if number("l4_source_port_first") != 0 or number("l4_source_port_last") != 65535:
    raise SystemExit("source port range mismatch")
if number("l4_destination_port_first") != expected_port:
    raise SystemExit("destination first port mismatch")
if number("l4_destination_port_last") != expected_port:
    raise SystemExit("destination last port mismatch")
if number("l4_priority") != 0 or number("l4_order") != 0:
    raise SystemExit("priority/order mismatch")
rule_id = number("l4_rule_id")
reason_id = number("l4_reason_id")
if rule_id <= 0 or reason_id <= 0:
    raise SystemExit("L4 rule/reason missing")
truthy("l4_facts_readback")
if number("policy_l4_active_revision") != active:
    raise SystemExit("policy_l4_active_revision mismatch")
if number("policy_l4_rule_id") != rule_id:
    raise SystemExit("policy_l4_rule_id mismatch")
if number("policy_l4_subject_uid") != expected_uid:
    raise SystemExit("policy_l4_subject_uid mismatch")
if number("policy_l4_network_context") != expected_context:
    raise SystemExit("policy_l4_network_context mismatch")
need("policy_l4_ip_family", "4")
need("policy_l4_ip_protocol", "6")
need("policy_l4_direction_code", "3")
if number("policy_l4_action_code") != expected_action:
    raise SystemExit("policy_l4_action_code mismatch")
if number("policy_l4_priority") != 0 or number("policy_l4_order") != 0:
    raise SystemExit("policy_l4 priority/order mismatch")
if number("policy_l4_reason_id") != reason_id:
    raise SystemExit("policy_l4_reason_id mismatch")
if require_match:
    truthy("l4_match_recorded")
    if number("policy_l4_match_records") <= 0:
        raise SystemExit("policy_l4_match_records missing")
    if number("policy_l4_last_match_revision") != active:
        raise SystemExit("policy_l4_last_match_revision mismatch")
    if number("policy_l4_last_match_rule_id") != rule_id:
        raise SystemExit("policy_l4_last_match_rule_id mismatch")
    if number("policy_l4_last_match_uid") != expected_uid:
        raise SystemExit("policy_l4_last_match_uid mismatch")
    if number("policy_l4_last_match_network_context") != expected_context:
        raise SystemExit("policy_l4_last_match_network_context mismatch")
    if number("policy_l4_last_match_reason_id") != reason_id:
        raise SystemExit("policy_l4_last_match_reason_id mismatch")
    need("policy_l4_last_match_winner", "2")
    if number("policy_l4_last_match_action") != expected_action:
        raise SystemExit("policy_l4_last_match_action mismatch")
    if number("policy_l4_last_match_verdict") != expected_action:
        raise SystemExit("policy_l4_last_match_verdict mismatch")
    need("policy_l4_last_match_device_direction_code", "3")
if require_drop:
    truthy("policy_drop_recorded")
    truthy("physical_nfqueue_completion")
    truthy("adapter_completion_separate")
    if number("policy_drop_records") <= 0:
        raise SystemExit("policy_drop_records missing")
    if number("policy_last_drop_revision") != active:
        raise SystemExit("policy_last_drop_revision mismatch")
    if number("policy_last_drop_rule_id") != rule_id:
        raise SystemExit("policy_last_drop_rule_id mismatch")
    if number("policy_last_drop_completion_attempts") != 1:
        raise SystemExit("policy_last_drop_completion_attempts mismatch")
    if number("policy_last_drop_uid") != expected_uid:
        raise SystemExit("policy_last_drop_uid mismatch")
    if number("policy_last_drop_network_context") != expected_context:
        raise SystemExit("policy_last_drop_network_context mismatch")
    if number("policy_last_drop_reason_id") != reason_id:
        raise SystemExit("policy_last_drop_reason_id mismatch")
    need("policy_last_drop_verdict", "2")
    need("policy_last_drop_winner", "2")
    truthy("policy_last_drop_uid_known")
    need("policy_last_drop_device_direction", "OUTPUT")
    need("policy_last_drop_device_direction_code", "3")
    need("expected_policy_last_drop_verdict", "2")
    need("expected_policy_last_drop_winner", "2")
    need("expected_policy_last_drop_device_direction", "3")
else:
    if expected_action_name == "allow":
        falsey("policy_drop_recorded")
if require_no_match:
    if number("policy_l4_no_match_records") <= 0:
        raise SystemExit("policy_l4_no_match_records missing")
    need("policy_l4_last_evaluation_result", "2")
    need("policy_l4_last_evaluation_verdict", "1")
    # A TCP echo includes reverse-direction packets; the final evaluation can
    # therefore be INPUT even when the configured rule remains OUTPUT.
print(f"active_revision={active}")
print(f"l4_rule_id={rule_id}")
print(f"l4_reason_id={reason_id}")
print(f"l4_action={expected_action_name}")
if require_match:
    print(f"policy_l4_match_records={number('policy_l4_match_records')}")
    print("l4_match_recorded=true")
if require_drop:
    print(f"policy_drop_records={number('policy_drop_records')}")
    print("policy_drop_recorded=true")
    print("physical_nfqueue_completion=true")
if require_no_match:
    print(f"policy_l4_no_match_records={number('policy_l4_no_match_records')}")
    print("no_match_pass_next=true")
PY
}

capture_s191_status() {
  local label="$1"
  local expected_stage="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_action="$5"
  local expected_port="$6"
  local min_revision="$7"
  local require_match="$8"
  local require_drop="$9"
  local require_no_match="${10}"
  local output="$RESULT_DIR/${label}.s191.properties"
  local values="$RESULT_DIR/${label}.s191.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S191_WAIT_ATTEMPTS"); do
    read_app_file "$S191_STATUS_PATH" > "$output"
    if validate_s191_status_file "$output" "$expected_stage" "$expected_uid" \
        "$expected_context" "$expected_action" "$expected_port" "$min_revision" \
        "$require_match" "$require_drop" "$require_no_match" \
        > "$values" 2>"$RESULT_DIR/${label}.s191.validation.stderr"; then
      while IFS= read -r line; do
        kv "${label}.${line%%=*}" "${line#*=}"
      done < "$values"
      kv "${label}.status_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} S191 status did not become valid; see ${output}"
}

validate_l4_store_matches() {
  local label="$1"
  local expected_revision="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_action="$5"
  local expected_port="$6"
  local expected_rule_id="$7"
  local expected_reason_id="$8"
  local store_file="$RESULT_DIR/${label}.policy-bundle.properties"
  read_app_file "$L4_STORE_PATH" > "$store_file"
  python3 - "$store_file" "$expected_revision" "$expected_uid" "$expected_context" \
    "$expected_action" "$expected_port" "$expected_rule_id" "$expected_reason_id" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_action = "2" if sys.argv[5] == "drop" else "1"
expected = {
    "schema": "sakamoto-policy-bundle/v1",
    "abiVersion": "1",
    "revision": sys.argv[2],
    "gateEntryCount": "0",
    "l4RuleCount": "1",
    "defaultPass": "1",
    "snapshotIdentity": "sakamoto-policy-bundle/v1",
    "l4.0.subjectUid": sys.argv[3],
    "l4.0.networkContext": sys.argv[4],
    "l4.0.ruleKind": "2",
    "l4.0.ipFamily": "4",
    "l4.0.ipProtocol": "6",
    "l4.0.direction": "3",
    "l4.0.action": expected_action,
    "l4.0.enabled": "1",
    "l4.0.sourcePrefixLen": "0",
    "l4.0.destinationPrefixLen": "32",
    "l4.0.sourcePortFirst": "0",
    "l4.0.sourcePortLast": "65535",
    "l4.0.destinationPortFirst": sys.argv[6],
    "l4.0.destinationPortLast": sys.argv[6],
    "l4.0.priority": "0",
    "l4.0.order": "0",
    "l4.0.ruleId": sys.argv[7],
    "l4.0.reasonId": sys.argv[8],
}
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value
for key, wanted in expected.items():
    actual = props.get(key, "")
    if actual != wanted:
        raise SystemExit(f"{key}={actual!r}, expected {wanted!r}")
snapshot_hash = int(props.get("snapshotHash", "0"))
if snapshot_hash <= 0:
    raise SystemExit("snapshotHash missing")
PY
  kv "${label}.rust_product_store_readback" true
}

wait_for_probe_result() {
  local label="$1"
  local expected="$2"
  local expected_uid="$3"
  local expected_nonce="$4"
  local output="$RESULT_DIR/${label}.traffic-probe.properties"
  local attempt
  for attempt in $(seq 1 "$S191_WAIT_ATTEMPTS"); do
    read_app_file "$TRAFFIC_PROBE_PATH" > "$output"
    if grep -Fq "nonce=${expected_nonce}" "$output" \
        && grep -Fq "result=${expected}" "$output"; then
      local uid
      uid="$(property_value "$output" uid)"
      if [[ "$uid" != "$expected_uid" ]]; then
        fail_closed "${label} probe UID $uid did not match installed app UID $expected_uid"
      fi
      kv "${label}.traffic" "$expected"
      kv "${label}.traffic_probe_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} traffic probe did not report ${expected}; see ${output}"
}

wait_for_host_ready() {
  local ready_file="$1"
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if [[ -f "$ready_file" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_tcp4_echo_server_once() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  local timeout_seconds="$6"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" \
    "$log_file" "$timeout_seconds" <<'PY' >"${log_file}.stdout" 2>"${log_file}.stderr" &
import pathlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])
timeout = int(sys.argv[6])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(1)
server.settimeout(timeout)
ready.write_text("ready\n", encoding="utf-8")

result = "tcp_echo_unseen"
matched = 0
request_bytes = 0
response_bytes = 0
peer = ""
received = b""
try:
    conn, address = server.accept()
    with conn:
        conn.settimeout(timeout)
        peer = f"{address[0]}:{address[1]}"
        received = conn.recv(4096)
        request_bytes = len(received)
        if received == expected:
            conn.sendall(received)
            response_bytes = len(received)
            matched = 1
            result = "tcp_echo_matched"
        else:
            result = "tcp_echo_mismatch"
except socket.timeout:
    result = "tcp_echo_unseen"
except Exception as error:
    result = f"tcp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    server.close()
    log.write_text(
        f"result={result}\nmatched={matched}\nrequestBytes={request_bytes}\n"
        f"responseBytes={response_bytes}\npeer={peer}\n"
        f"received={received.decode(errors='replace')}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

run_app_tcp_probe_with_server() {
  local label="$1"
  local probe_port="$2"
  local nonce="$3"
  local expected_probe="$4"
  local expected_server="$5"
  local uid="$6"
  local ready_file="$RESULT_DIR/${label}.tcp4.ready"
  local server_log="$RESULT_DIR/${label}.tcp4.server.log"
  local timeout_seconds=$(((timeout_ms + 1999) / 1000))
  if (( timeout_seconds < 2 )); then
    timeout_seconds=2
  fi

  rm -f "$ready_file" "$server_log"
  start_tcp4_echo_server_once "0.0.0.0" "$probe_port" "$nonce" "$ready_file" \
    "$server_log" "$timeout_seconds"
  if ! wait_for_host_ready "$ready_file"; then
    if [[ -n "$server_pid" ]]; then
      kill "$server_pid" >/dev/null 2>&1 || true
      wait "$server_pid" >/dev/null 2>&1 || true
      server_pid=""
    fi
    fail_closed "${label} echo server did not become ready; see ${server_log}.stderr"
  fi
  clear_app_file "$TRAFFIC_PROBE_PATH"
  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$controlled_host" \
    --ei debugTrafficPort "$probe_port" \
    --es debugTrafficNonce "$nonce" \
    --ei debugTrafficTimeoutMillis "$timeout_ms"
  wait_for_probe_result "$label" "$expected_probe" "$uid" "$nonce"
  wait "$server_pid" || true
  server_pid=""
  if ! grep -Fq "result=${expected_server}" "$server_log"; then
    fail_closed "${label} server expected ${expected_server}; see ${server_log}"
  fi
  kv "${label}.server" "$expected_server"
}

installed_app_uid() {
  local list_output="$RESULT_DIR/package-list.txt"
  local dumpsys_output="$RESULT_DIR/package-dumpsys.txt"
  local uid=""
  adb_target shell cmd package list packages -U "$PACKAGE" \
    > "$list_output" 2>/dev/null || true
  uid="$(tr -d '\r' < "$list_output" \
    | awk -v package="package:${PACKAGE}" '$1 == package { for (i = 1; i <= NF; i++) { if ($i ~ /^uid:/) { sub(/^uid:/, "", $i); print $i; exit } } }')"
  if [[ -z "$uid" ]]; then
    adb_target shell dumpsys package "$PACKAGE" > "$dumpsys_output" 2>/dev/null || true
    uid="$(tr -d '\r' < "$dumpsys_output" \
      | awk -F= '/userId=/{ gsub(/[^0-9].*/, "", $2); print $2; exit }')"
  fi
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || (( uid <= 0 )); then
    fail_closed "could not discover installed APK complete UID for $PACKAGE"
  fi
  printf '%s\n' "$uid"
}

stop_runtime() {
  clear_app_file "$STATE_PATH"
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  wait_for_state stopped >/dev/null 2>&1 || true
}

apply_l4_rule() {
  local action="$1"
  local subject="$2"
  start_activity \
    --es debugSetL4RuleSubject "$subject" \
    --es debugSetL4RuleFamily ipv4 \
    --es debugSetL4RuleSourceCidr "0.0.0.0/0" \
    --es debugSetL4RuleDestinationCidr "${controlled_host}/32" \
    --ei debugSetL4RuleSourcePortFirst 0 \
    --ei debugSetL4RuleSourcePortLast 65535 \
    --ei debugSetL4RuleDestinationPortFirst "$port" \
    --ei debugSetL4RuleDestinationPortLast "$port" \
    --ei debugSetL4RuleIpProtocol 6 \
    --es debugSetL4RuleDirection output \
    --es debugSetL4RuleNetworkContext wifi \
    --es debugSetL4RuleAction "$action" \
    --ei debugSetL4RulePriority 0 \
    --ei debugSetL4RuleOrder 0
}

kv acceptance SAKAMOTO-191-root-tcp4-l4
kv serial "$serial"
kv package "$PACKAGE"
kv host "$controlled_host"
kv port "$port"
kv no_match_port "$nomatch_port"
kv result_dir "$RESULT_DIR"

acquire_run_lock

if ! adb_devices_contains_serial; then
  fail_closed "adb devices does not show $serial as device"
fi
kv adb_devices_contains_serial true

adb_target get-state > "$RESULT_DIR/adb-get-state.txt"
kv adb_get_state "$(tr -d '\r\n' < "$RESULT_DIR/adb-get-state.txt")"
read_device_model "$RESULT_DIR/device-model.txt" \
  || fail_closed "could not read controlled Pixel 6a model from ADB"
if ! grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt"; then
  fail_closed "connected serial is not the controlled Pixel 6a"
fi
kv device_model "$(cat "$RESULT_DIR/device-model.txt")"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true

app_uid="$(installed_app_uid)"
subject="android.uid:${app_uid}"
kv installed_app_uid "$app_uid"
kv installed_app_uid_complete true
kv network_context wifi
kv network_context_id 1

stop_runtime
cleanup_product_state_for_acceptance

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_running_root

start_activity --ez debugApplyEmptyPolicy true
wait_for_s188_empty

baseline_nonce="s191-baseline-${RUN_ID}"
run_app_tcp_probe_with_server baseline "$port" "$baseline_nonce" \
  tcp_echo_matched tcp_echo_matched "$app_uid"
kv baseline_traffic tcp_echo_matched

clear_app_file "$S191_STATUS_PATH"
apply_l4_rule drop "$subject"
capture_s191_status l4_drop_apply l4_apply "$app_uid" 1 drop "$port" 0 false false false
drop_revision="$(property_value "$RESULT_DIR/l4_drop_apply.s191.summary-fragment.properties" active_revision)"
drop_rule_id="$(property_value "$RESULT_DIR/l4_drop_apply.s191.summary-fragment.properties" l4_rule_id)"
drop_reason_id="$(property_value "$RESULT_DIR/l4_drop_apply.s191.summary-fragment.properties" l4_reason_id)"
validate_l4_store_matches l4_drop_apply "$drop_revision" "$app_uid" 1 drop "$port" \
  "$drop_rule_id" "$drop_reason_id"
kv l4_drop true

blocked_nonce="s191-blocked-${RUN_ID}"
run_app_tcp_probe_with_server blocked "$port" "$blocked_nonce" \
  tcp_connect_failed tcp_echo_unseen "$app_uid"
kv blocked_traffic tcp_connect_failed

start_activity --ez debugRefresh true
capture_s191_status l4_drop - "$app_uid" 1 drop "$port" \
  $((drop_revision - 1)) true true false
drop_records_after_blocked="$(number_property \
  "$RESULT_DIR/l4_drop.s191.properties" policy_drop_records)"

nomatch_nonce="s191-no-match-${RUN_ID}"
run_app_tcp_probe_with_server no_match "$nomatch_port" "$nomatch_nonce" \
  tcp_echo_matched tcp_echo_matched "$app_uid"
kv no_match_traffic tcp_echo_matched
start_activity --ez debugRefresh true
capture_s191_status l4_no_match - "$app_uid" 1 drop "$port" \
  $((drop_revision - 1)) false false true
no_match_drop_records="$(number_property \
  "$RESULT_DIR/l4_no_match.s191.properties" policy_drop_records)"
if (( no_match_drop_records != drop_records_after_blocked )); then
  fail_closed "no-match traffic changed L4 drop records"
fi
kv no_match_pass_next true

repeat_nonce="s191-repeat-drop-${RUN_ID}"
run_app_tcp_probe_with_server repeat_drop "$port" "$repeat_nonce" \
  tcp_connect_failed tcp_echo_unseen "$app_uid"
kv repeat_drop_traffic tcp_connect_failed
start_activity --ez debugRefresh true
capture_s191_status l4_repeat_drop - "$app_uid" 1 drop "$port" \
  $((drop_revision - 1)) true true false
kv deterministic_precedence priority_order_rule_id

clear_app_file "$S191_STATUS_PATH"
apply_l4_rule allow "$subject"
capture_s191_status l4_allow_apply l4_apply "$app_uid" 1 allow "$port" \
  "$drop_revision" false false false
allow_revision="$(property_value "$RESULT_DIR/l4_allow_apply.s191.summary-fragment.properties" active_revision)"
allow_rule_id="$(property_value "$RESULT_DIR/l4_allow_apply.s191.summary-fragment.properties" l4_rule_id)"
allow_reason_id="$(property_value "$RESULT_DIR/l4_allow_apply.s191.summary-fragment.properties" l4_reason_id)"
if [[ "$allow_rule_id" != "$drop_rule_id" ]]; then
  fail_closed "allow successor rule id $allow_rule_id did not match drop rule id $drop_rule_id"
fi
validate_l4_store_matches l4_allow_apply "$allow_revision" "$app_uid" 1 allow "$port" \
  "$allow_rule_id" "$allow_reason_id"
kv l4_allow true
kv l4_successor_same_rule_id true

allow_nonce="s191-allow-${RUN_ID}"
run_app_tcp_probe_with_server allow_restore "$port" "$allow_nonce" \
  tcp_echo_matched tcp_echo_matched "$app_uid"
kv allow_restore_traffic tcp_echo_matched
start_activity --ez debugRefresh true
capture_s191_status l4_allow_match - "$app_uid" 1 allow "$port" \
  $((allow_revision - 1)) true false false

adb_target shell input keyevent HOME >/dev/null 2>&1 || true
start_activity --ez debugRefresh true
capture_s191_status activity_reconnect - "$app_uid" 1 allow "$port" \
  $((allow_revision - 1)) false false false
activity_reconnect_revision="$(property_value "$RESULT_DIR/activity_reconnect.s191.summary-fragment.properties" active_revision)"
if [[ "$activity_reconnect_revision" != "$allow_revision" ]]; then
  fail_closed "Activity reconnect revision $activity_reconnect_revision did not match allow revision $allow_revision"
fi
kv activity_reconnect_authoritative_revision "$activity_reconnect_revision"
kv activity_reconnect_same_revision true

stop_runtime
if ! wait_for_state stopped >/dev/null 2>&1; then
  fail_closed "Root Product Core did not stop cleanly before restart"
fi
read_app_file "$STATE_PATH" > "$RESULT_DIR/state.stopped-before-restart.properties"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.stopped-before-restart.properties"; then
  fail_closed "stopped-before-restart state still reports mayBeActive=true"
fi
kv stopped_before_restart_clean true

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_running_root
capture_s191_status restart_after_allow - "$app_uid" 1 allow "$port" \
  $((allow_revision - 1)) false false false
restart_after_allow_revision="$(property_value "$RESULT_DIR/restart_after_allow.s191.summary-fragment.properties" active_revision)"
if [[ "$restart_after_allow_revision" != "$allow_revision" ]]; then
  fail_closed "restart revision $restart_after_allow_revision did not match allow revision $allow_revision"
fi
kv restart_after_allow_authoritative_revision "$restart_after_allow_revision"
kv restart_after_allow_same_revision true

restart_nonce="s191-restart-${RUN_ID}"
run_app_tcp_probe_with_server restart_after_allow "$port" "$restart_nonce" \
  tcp_echo_matched tcp_echo_matched "$app_uid"
kv restart_after_allow_traffic tcp_echo_matched
start_activity --ez debugRefresh true
capture_s191_status restart_after_allow_match - "$app_uid" 1 allow "$port" \
  $((allow_revision - 1)) true false false

stop_runtime
if ! wait_for_state stopped >/dev/null 2>&1; then
  fail_closed "Root Product Core did not stop cleanly"
fi
read_app_file "$STATE_PATH" > "$RESULT_DIR/state.stopped.properties"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.stopped.properties"; then
  fail_closed "stopped state still reports mayBeActive=true"
fi
kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-191 Root TCP4 L4: PASS"
