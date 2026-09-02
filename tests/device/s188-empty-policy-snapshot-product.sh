#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-188 empty immutable policy snapshot publication/readback.
#
# PASS means the installed debug APK starts Product Core on the controlled
# Pixel 6a, persists an empty authoring intent through Rust Product Store,
# publishes a complete empty default-pass runtime snapshot through the
# current-generation serialized VAPI session, reads the active revision/status
# back, explicitly publishes one fresh empty revision, then starts VPN and
# proves the persisted revision is reconciled there without Gate/L4 claims.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S188_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s188-empty-policy-snapshot}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s188-device-run.lock"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s188-empty-policy-snapshot.properties"
readonly STORE_PATH="files/product-policy/empty-intent.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly PRODUCT_TRANSACTIONS_TEMP_PATH="files/product-transactions/transactions.properties.tmp"
readonly POLICY_BUNDLE_PATH="files/product-policy/policy-bundle.properties"
readonly POLICY_BUNDLE_TEMP_PATH="files/product-policy/policy-bundle.properties.tmp"
readonly NETWORK_GATE_STORE_PATH="files/product-policy/network-gate-intent.properties"
readonly NETWORK_GATE_STORE_TEMP_PATH="files/product-policy/network-gate-intent.properties.tmp"
readonly L4_STORE_PATH="files/product-policy/l4-intent.properties"
readonly L4_STORE_TEMP_PATH="files/product-policy/l4-intent.properties.tmp"
readonly EMPTY_STORE_TEMP_PATH="files/product-policy/empty-intent.properties.tmp"
readonly S188_WAIT_ATTEMPTS="${S188_WAIT_ATTEMPTS:-240}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s188-empty-policy-snapshot-product.sh --run

Optional:
  --serial 28201JEGR0XPAJ

Before running, install the debug APK, approve it as an Android VPN service,
and grant root in KernelSU Manager. Device PASS is the only PASS.
EOF
}

serial="$S188_SERIAL"
run=0

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

if [[ "$serial" != "$S188_SERIAL" ]]; then
  echo "SAKAMOTO-188 only accepts controlled Pixel 6a serial $S188_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"
run_lock_acquired=0

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if "$ADB" "$@"; then
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

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

clear_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" rm -f "$relative" >/dev/null 2>&1 || true
}

clear_authoring_policy_files() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" \
    "$STATUS_PATH" \
    "$PRODUCT_STATE_PATH" \
    "$PRODUCT_TRANSACTIONS_PATH" \
    "$PRODUCT_TRANSACTIONS_TEMP_PATH" \
    "$STORE_PATH" \
    "$EMPTY_STORE_TEMP_PATH" \
    "$POLICY_BUNDLE_PATH" \
    "$POLICY_BUNDLE_TEMP_PATH" \
    "$NETWORK_GATE_STORE_PATH" \
    "$NETWORK_GATE_STORE_TEMP_PATH" \
    "$L4_STORE_PATH" \
    "$L4_STORE_TEMP_PATH" >/dev/null 2>&1 || true
}

assert_authoring_policy_files_cleared() {
  local relative
  local contents
  for relative in \
    "$PRODUCT_TRANSACTIONS_PATH" \
    "$PRODUCT_TRANSACTIONS_TEMP_PATH" \
    "$STORE_PATH" \
    "$EMPTY_STORE_TEMP_PATH" \
    "$POLICY_BUNDLE_PATH" \
    "$POLICY_BUNDLE_TEMP_PATH" \
    "$NETWORK_GATE_STORE_PATH" \
    "$NETWORK_GATE_STORE_TEMP_PATH" \
    "$L4_STORE_PATH" \
    "$L4_STORE_TEMP_PATH"; do
    contents="$(read_app_file "$relative")"
    if [[ -n "$contents" ]]; then
      fail_closed "S188 authoring policy precondition retained $relative"
    fi
  done
  kv preflight_authoring_policy_cleared true
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "$RESULT_DIR/am-start.log" 2>&1
}

cleanup() {
  local status=$?
  set +e
  if [[ "$run_lock_acquired" == 1 ]]; then
    start_activity --ez runtimeStop true >/dev/null 2>&1 || true
    rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-188 FAIL: $1" >&2
  exit 1
}

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
    if [[ "$lock_args" == *"s188-empty-policy-snapshot-product.sh"* ]]; then
      fail_closed "another S188 runner is active: pid=$lock_pid"
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
  fail_closed "could not acquire S188 device run lock"
}

property_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' "$file"
}

wait_for_state() {
  local expected="$1"
  local output="$RESULT_DIR/state-${expected}.properties"
  local attempt
  for attempt in $(seq 1 "$S188_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fq "state=${expected}" "$output"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

current_runtime_generation() {
  local output="$RESULT_DIR/current-state.properties"
  local value=""
  read_app_file "$STATE_PATH" > "$output"
  value="$(property_value "$output" generation || true)"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    value=0
  fi
  printf '%s\n' "$value"
}

wait_for_running_profile() {
  local label="$1"
  local expected_profile="$2"
  local expected_adapter="$3"
  local min_generation="$4"
  local output="$RESULT_DIR/${label}.runtime-state.properties"
  local values="$RESULT_DIR/${label}.runtime-state.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S188_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if validate_runtime_state_file "$output" "$expected_profile" "$expected_adapter" "$min_generation" \
        > "$values" 2>"$RESULT_DIR/${label}.runtime-state.stderr"; then
      while IFS= read -r line; do
        kv "${label}.runtime.${line%%=*}" "${line#*=}"
      done < "$values"
      kv "${label}.running_state_file" "$output"
      return 0
    fi
    if grep -Fq 'errorCode=root_authorization_required' "$output"; then
      fail_closed "${label} start requires KernelSU superuser grant"
    fi
    if grep -Fq 'errorCode=vpn_authorization_required' "$output"; then
      fail_closed "${label} start requires Android VPN authorization"
    fi
    if grep -Fq 'errorCode=notification_permission_required' "$output"; then
      fail_closed "${label} start requires Android notification permission"
    fi
    sleep 0.5
  done
  fail_closed "${label} did not reach new running/${expected_profile}/${expected_adapter}; see ${output}"
}

validate_runtime_state_file() {
  local file="$1"
  local expected_profile="$2"
  local expected_adapter="$3"
  local min_generation="$4"
  python3 - "$file" "$expected_profile" "$expected_adapter" "$min_generation" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_profile = sys.argv[2]
expected_adapter = sys.argv[3]
min_generation = int(sys.argv[4])
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


try:
    generation = int(need("generation"))
except ValueError as error:
    raise SystemExit("generation is not numeric") from error
if generation <= min_generation:
    raise SystemExit(f"generation={generation}, expected > {min_generation}")
need("state", "running")
need("profile", expected_profile)
need("adapterReadiness", expected_adapter)
need("coreHealth", "ok")
need("errorCode", "")
need("mayBeActive", "true")
print(f"generation={generation}")
print(f"adapterReadiness={props['adapterReadiness']}")
PY
}

validate_s188_status_file() {
  local file="$1"
  local expected_profile="$2"
  local min_revision="$3"
  local expected_generation="$4"
  python3 - "$file" "$expected_profile" "$min_revision" "$expected_generation" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_profile = sys.argv[2]
min_revision = int(sys.argv[3])
expected_generation = int(sys.argv[4])
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


need("schema", "s188-empty-policy-snapshot/v1")
need("profile", expected_profile)
need("state", "running")
need("errorCode", "")
requested = number("requested_revision")
active = number("active_revision")
policy_generation = number("policy_generation")
status_generation = number("generation")
snapshot_hash = number("policy_snapshot_hash")
if requested < min_revision:
    raise SystemExit(f"requested_revision={requested}, expected >= {min_revision}")
if requested <= 0 or active <= 0 or requested != active:
    raise SystemExit("requested/active revision mismatch")
if policy_generation != status_generation or policy_generation <= 0:
    raise SystemExit("policy generation mismatch")
if expected_generation > 0 and status_generation != expected_generation:
    raise SystemExit(
        f"generation={status_generation}, expected {expected_generation}"
    )
if snapshot_hash <= 0:
    raise SystemExit("snapshot hash missing")
truthy("revision_match")
truthy("generation_match")
truthy("policy_snapshot_empty")
truthy("policy_default_pass")
truthy("empty_default_pass")
truthy("no_gate_l4_claim")
truthy("worker_revision_match")
truthy("artifact_match")
truthy("rust_product_store_single_writer")
falsey("ui_policy_authority")
falsey("vpp_policy_authority")
falsey("traffic_behavior_changed")
if number("gate_claim_count") != 0 or number("l4_rule_count") != 0:
    raise SystemExit("Gate/L4 claim count must stay zero")
if number("submission_status_code") != 0 or number("operation_status_code") != 0:
    raise SystemExit("policy apply/query status code must be zero")
need("policy_snapshot_identity")
need("artifact_id")
need("api_identity")
need("vpp_revision")

print(f"requested_revision={requested}")
print(f"active_revision={active}")
print(f"generation={status_generation}")
print(f"policy_generation={policy_generation}")
print(f"policy_snapshot_hash={snapshot_hash}")
print(f"policy_snapshot_identity={props['policy_snapshot_identity']}")
PY
}

capture_s188_status() {
  local label="$1"
  local expected_profile="$2"
  local min_revision="$3"
  local expected_generation="$4"
  local output="$RESULT_DIR/${label}.s188.properties"
  local values="$RESULT_DIR/${label}.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S188_WAIT_ATTEMPTS"); do
    read_app_file "$STATUS_PATH" > "$output"
    if validate_s188_status_file "$output" "$expected_profile" "$min_revision" "$expected_generation" > "$values" 2>"$RESULT_DIR/${label}.validation.stderr"; then
      while IFS= read -r line; do
        kv "${label}.${line%%=*}" "${line#*=}"
      done < "$values"
      kv "${label}.status_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} S188 status did not become valid; see ${output} and ${RESULT_DIR}/${label}.validation.stderr"
}

validate_store_matches() {
  local expected_revision="$1"
  local expected_hash="$2"
  local expected_identity="$3"
  local store_file="$RESULT_DIR/empty-intent.properties"
  read_app_file "$STORE_PATH" > "$store_file"
  python3 - "$store_file" "$expected_revision" "$expected_hash" "$expected_identity" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_revision = sys.argv[2]
expected_hash = sys.argv[3]
expected_identity = sys.argv[4]
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value
checks = {
    "schema": "sakamoto-empty-policy-intent/v1",
    "revision": expected_revision,
    "snapshotHash": expected_hash,
    "snapshotIdentity": expected_identity,
    "empty": "true",
    "defaultPass": "true",
    "gateClaimCount": "0",
    "l4RuleCount": "0",
}
for key, expected in checks.items():
    actual = props.get(key, "")
    if actual != expected:
        raise SystemExit(f"{key}={actual!r}, expected {expected!r}")
PY
  kv rust_product_store_readback true
  kv rust_product_store_file "$store_file"
}

start_profile() {
  local label="$1"
  local profile="$2"
  local min_generation="$3"
  local expected_adapter="root-nfqueue"
  if [[ "$profile" == vpn ]]; then
    expected_adapter="vpn-tun-hev-lwip"
  fi
  clear_app_file "$STATE_PATH"
  clear_app_file "$STATUS_PATH"
  kv "${profile}.start_requested" true
  kv "${label}.start_min_generation" "$min_generation"
  start_activity --ez runtimeStart true --es runtimeProfile "$profile"
  wait_for_running_profile "$label" "$profile" "$expected_adapter" "$min_generation"
}

stop_runtime() {
  clear_app_file "$STATE_PATH"
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  if ! wait_for_state stopped >/dev/null 2>&1; then
    fail_closed "runtime did not reach stopped state"
  fi
}

kv acceptance SAKAMOTO-188-empty-policy-snapshot
kv serial "$serial"
kv package "$PACKAGE"
kv result_dir "$RESULT_DIR"

acquire_run_lock

if ! adb_devices_contains_serial; then
  fail_closed "adb devices does not show $serial as device"
fi
kv adb_devices_contains_serial true

adb_target get-state > "$RESULT_DIR/adb-get-state.txt"
kv adb_get_state "$(tr -d '\r\n' < "$RESULT_DIR/adb-get-state.txt")"

stop_runtime
adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
kv preflight_force_stop_after_install true
clear_authoring_policy_files
assert_authoring_policy_files_cleared

root_start_before_generation="$(current_runtime_generation)"
start_profile root_start root "$root_start_before_generation"
root_start_generation="$(property_value "$RESULT_DIR/root_start.runtime-state.summary-fragment.properties" generation)"
capture_s188_status root_start root 1 "$root_start_generation"
root_start_revision="$(property_value "$RESULT_DIR/root_start.summary-fragment.properties" active_revision)"

clear_app_file "$STATUS_PATH"
start_activity --ez debugApplyEmptyPolicy true
capture_s188_status root_apply root $((root_start_revision + 1)) "$root_start_generation"
root_apply_revision="$(property_value "$RESULT_DIR/root_apply.summary-fragment.properties" active_revision)"
root_apply_hash="$(property_value "$RESULT_DIR/root_apply.summary-fragment.properties" policy_snapshot_hash)"
root_apply_identity="$(property_value "$RESULT_DIR/root_apply.summary-fragment.properties" policy_snapshot_identity)"

validate_store_matches "$root_apply_revision" "$root_apply_hash" "$root_apply_identity"

stop_runtime
root_restart_before_generation="$(current_runtime_generation)"
start_profile root_restart root "$root_restart_before_generation"
root_restart_generation="$(property_value "$RESULT_DIR/root_restart.runtime-state.summary-fragment.properties" generation)"
capture_s188_status root_restart root "$root_apply_revision" "$root_restart_generation"
root_restart_revision="$(property_value "$RESULT_DIR/root_restart.summary-fragment.properties" active_revision)"
root_restart_hash="$(property_value "$RESULT_DIR/root_restart.summary-fragment.properties" policy_snapshot_hash)"
root_restart_identity="$(property_value "$RESULT_DIR/root_restart.summary-fragment.properties" policy_snapshot_identity)"

if [[ "$root_restart_revision" != "$root_apply_revision" ]]; then
  fail_closed "Root restart reconciled revision $root_restart_revision does not match applied revision $root_apply_revision"
fi
if [[ "$root_restart_hash" != "$root_apply_hash" ]]; then
  fail_closed "Root restart snapshot hash $root_restart_hash does not match applied hash $root_apply_hash"
fi
if [[ "$root_restart_identity" != "$root_apply_identity" ]]; then
  fail_closed "Root restart snapshot identity $root_restart_identity does not match applied identity $root_apply_identity"
fi
kv root_restart_same_revision true
kv root_restart_same_snapshot_hash true
kv root_restart_same_snapshot_identity true

stop_runtime
vpn_before_generation="$(current_runtime_generation)"
start_profile vpn_reconcile vpn "$vpn_before_generation"
vpn_generation="$(property_value "$RESULT_DIR/vpn_reconcile.runtime-state.summary-fragment.properties" generation)"
capture_s188_status vpn_reconcile vpn "$root_apply_revision" "$vpn_generation"
vpn_revision="$(property_value "$RESULT_DIR/vpn_reconcile.summary-fragment.properties" active_revision)"
vpn_hash="$(property_value "$RESULT_DIR/vpn_reconcile.summary-fragment.properties" policy_snapshot_hash)"
vpn_identity="$(property_value "$RESULT_DIR/vpn_reconcile.summary-fragment.properties" policy_snapshot_identity)"

if [[ "$vpn_revision" != "$root_apply_revision" ]]; then
  fail_closed "VPN reconciled revision $vpn_revision does not match Root applied revision $root_apply_revision"
fi
if [[ "$vpn_hash" != "$root_apply_hash" ]]; then
  fail_closed "VPN snapshot hash $vpn_hash does not match Root snapshot hash $root_apply_hash"
fi
if [[ "$vpn_identity" != "$root_apply_identity" ]]; then
  fail_closed "VPN snapshot identity $vpn_identity does not match Root snapshot identity $root_apply_identity"
fi
kv root_vpn_same_revision true
kv root_vpn_same_snapshot_hash true
kv root_vpn_same_snapshot_identity true

stop_runtime
wait_for_state stopped >/dev/null 2>&1 || true

kv result PASS
echo "SAKAMOTO-188 empty policy snapshot: PASS"
