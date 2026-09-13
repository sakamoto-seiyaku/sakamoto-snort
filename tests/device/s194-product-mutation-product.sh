#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-194 typed Product policy mutation fault acceptance.
#
# The debug-only typed seam supports two explicit acceptance modes.  Callback
# omission records the ambiguous outcome, proves same-generation fencing, and
# requires fresh-generation readback-only reconciliation.  Pre-submit
# not-sent records a definite failure, proves no VAPI submission or fence, and
# requires an explicit retry.  The APK is not installed unless --install-apk
# is supplied; this keeps a previously restored KernelSU grant intact when
# --apk is used only for provenance.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S194_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s194-product-mutation}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly S194_STATUS_PATH="files/product-state/s194-product-mutation.properties"
readonly FAULT_STATUS_PATH="files/debug/policy-mutation-fault.properties"
readonly POLICY_BUNDLE_PATH="files/product-policy/policy-bundle.properties"
readonly POLICY_FENCE_PATH="files/product-policy/policy-mutation-fence.properties"
readonly POLICY_CANDIDATE_PATH="files/product-policy/policy-mutation-candidate.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly PRODUCT_GENERATION_STATE_PATH="files/product-state/product-core-generation.properties"
readonly ROOT_OWNER_PATH="files/profiles/root/vpp/owner.properties"
readonly ROOT_RUNTIME_DIR="files/profiles/root/vpp/runtime"
readonly RUNTIME_LOG_PATH="files/logs/runtime-service.log"
readonly ROOT_API_SOCKET_PATH="files/profiles/root/vpp/runtime/api.sock"
readonly WAIT_ATTEMPTS="${S194_WAIT_ATTEMPTS:-120}"
readonly ADB_TIMEOUT_SECONDS="${S194_ADB_COMMAND_TIMEOUT_SECONDS:-20}"
readonly EXPECTED_UID="${S194_EXPECTED_UID:-12632}"

serial="$S194_SERIAL"
apk="${S194_APK:-}"
stage="${S194_STAGE:-}"
source_root="${S194_SOURCE:-${repo_root}}"
result_dir="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
install_apk="${S194_INSTALL_APK:-0}"
fault_mode="${S194_FAULT_MODE:-bundle_callback_omission}"
run=0

usage() {
  cat <<'EOF'
Usage:
  tests/device/s194-product-mutation-product.sh --run [options]

Required:
  --run

Options:
  --apk <path>          Record and pin local APK provenance.
  --stage <path>        Record the product stage used to build the APK.
  --source <path>       Record the source tree or revision used to build it.
  --install-apk         Install --apk with ./dev/adb before acceptance.
  --serial 28201JEGR0XPAJ
  --result-dir <path>   Fresh evidence directory.
  --fault-mode <mode>   bundle_callback_omission or
                        bundle_pre_submit_not_sent (default: bundle_callback_omission).

The runner expects the debug APK to have KernelSU Superuser permission and the
Android notification permission.  --install-apk can reset the KernelSU grant;
restore it in KernelSU Manager before rerunning.  Device actions are all
performed through the repository-local ./dev/adb wrapper.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run)
      run=1
      shift
      ;;
    --apk)
      apk="${2:-}"
      shift 2
      ;;
    --stage)
      stage="${2:-}"
      shift 2
      ;;
    --source)
      source_root="${2:-}"
      shift 2
      ;;
    --install-apk)
      install_apk=1
      shift
      ;;
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --result-dir)
      result_dir="${2:-}"
      shift 2
      ;;
    --fault-mode)
      fault_mode="${2:-}"
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

if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ "$serial" != "$S194_SERIAL" ]]; then
  echo "SAKAMOTO-194 only accepts controlled Pixel 6a serial $S194_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$install_apk" == 1 && -z "$apk" ]]; then
  echo "--install-apk requires --apk <path>" >&2
  exit 2
fi
case "$fault_mode" in
  bundle_callback_omission|bundle_pre_submit_not_sent)
    ;;
  *)
    echo "unsupported --fault-mode: $fault_mode" >&2
    usage >&2
    exit 2
    ;;
esac
if [[ -n "$apk" && ! -f "$apk" ]]; then
  echo "APK does not exist: $apk" >&2
  exit 2
fi
if [[ -n "$stage" && ! -e "$stage" ]]; then
  echo "product stage does not exist: $stage" >&2
  exit 2
fi

mkdir -p "$result_dir"
readonly RESULT_DIR="$result_dir"
readonly SUMMARY="${RESULT_DIR}/summary.properties"
readonly RUN_LOCK_DIR="${S194_RUN_LOCK_DIR:-$(dirname -- "$RESULT_DIR")/.s194-device-run.lock}"
: > "$SUMMARY"

run_lock_acquired=0
runtime_started=0
failure_recorded=0
acceptance_complete=0
app_uid=""
subject=""
pre_submit_generation=""
pre_submit_handle=""
callback_generation=""
callback_handle=""
fresh_generation=""
fresh_handle=""
root_handle=""

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$SUMMARY"
}

fail_closed() {
  local message="$1"
  if [[ "$failure_recorded" == 0 ]]; then
    failure_recorded=1
    kv result FAIL
    kv failure "$message"
  fi
  echo "SAKAMOTO-194 FAIL: $message" >&2
  exit 1
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if timeout "$ADB_TIMEOUT_SECONDS" "$ADB" "$@"; then
      return 0
    else
      # Capture the failing timeout/ADB status in the else branch.  Reading
      # `$?` after an `if` compound command would otherwise turn a remote
      # non-zero result into success in bash, making missing files look
      # present to the residue checks.
      rc=$?
    fi
    sleep 1
  done
  return "$rc"
}

adb_target() {
  adb_raw -s "$serial" "$@"
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null \
    | tr -d '\r' || true
}

capture_remote_file() {
  local relative="$1"
  local output="$2"
  : > "$output"
  adb_target shell run-as "$PACKAGE" cat "$relative" \
    > "$output" 2> "${output}.stderr" || true
  tr -d '\r' < "$output" > "${output}.tmp" || true
  mv -f "${output}.tmp" "$output" 2>/dev/null || true
}

clear_remote_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" rm -f "$relative" \
    >/dev/null 2>&1 || true
}

remote_file_exists() {
  local relative="$1"
  # Keep the predicate as a direct run-as command.  The Windows ADB bridge
  # used by ./dev/adb does not preserve a nested `sh -c` command string
  # reliably; `cat`/`test` as direct run-as commands share the same cwd and
  # return the actual app-private file status.
  adb_target shell run-as "$PACKAGE" test -f "$relative" \
    >/dev/null 2>&1
}

remote_path_exists() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" test -e "$relative" \
    >/dev/null 2>&1
}

property_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" \
    '$1 == key { print substr($0, length(key) + 2); exit }' "$file"
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "${RESULT_DIR}/am-start.log" 2>&1
}

acquire_run_lock() {
  mkdir -p "$(dirname -- "$RUN_LOCK_DIR")"
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "${RUN_LOCK_DIR}/pid"
    kv device_run_lock_acquired true
    return 0
  fi

  local lock_pid=""
  if [[ -f "${RUN_LOCK_DIR}/pid" ]]; then
    lock_pid="$(tr -cd '0-9' < "${RUN_LOCK_DIR}/pid" 2>/dev/null || true)"
  fi
  if [[ -n "$lock_pid" && "$lock_pid" != "$$" ]] \
      && kill -0 "$lock_pid" 2>/dev/null; then
    fail_closed "another S194 device runner owns ${RUN_LOCK_DIR}: pid=${lock_pid}"
  fi
  kv stale_run_lock_recovered true
  rm -f "${RUN_LOCK_DIR}/pid" >/dev/null 2>&1 || true
  rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 \
    || fail_closed "stale S194 lock is not empty: ${RUN_LOCK_DIR}"
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "${RUN_LOCK_DIR}/pid"
    kv device_run_lock_acquired true
    return 0
  fi
  fail_closed "could not acquire S194 device run lock: ${RUN_LOCK_DIR}"
}

capture_phase() {
  local label="$1"
  capture_remote_file "$STATE_PATH" "${RESULT_DIR}/${label}.runtime-state.properties"
  capture_remote_file "$S194_STATUS_PATH" "${RESULT_DIR}/${label}.s194-product-mutation.properties"
  capture_remote_file "$FAULT_STATUS_PATH" "${RESULT_DIR}/${label}.policy-mutation-fault.properties"
  capture_remote_file "$POLICY_BUNDLE_PATH" "${RESULT_DIR}/${label}.policy-bundle.properties"
  capture_remote_file "$POLICY_FENCE_PATH" "${RESULT_DIR}/${label}.policy-mutation-fence.properties"
  capture_remote_file "$POLICY_CANDIDATE_PATH" "${RESULT_DIR}/${label}.policy-mutation-candidate.properties"
  capture_remote_file "$PRODUCT_STATE_PATH" "${RESULT_DIR}/${label}.product.properties"
  capture_remote_file "$PRODUCT_TRANSACTIONS_PATH" "${RESULT_DIR}/${label}.transactions.properties"
  capture_remote_file "$PRODUCT_GENERATION_STATE_PATH" \
    "${RESULT_DIR}/${label}.product-core-generation.properties"
  capture_remote_file "$ROOT_OWNER_PATH" "${RESULT_DIR}/${label}.root-owner.properties"
  capture_remote_file "$RUNTIME_LOG_PATH" "${RESULT_DIR}/${label}.runtime-service.log"
}

capture_device_snapshot() {
  local label="$1"
  adb_target shell dumpsys package "$PACKAGE" \
    > "${RESULT_DIR}/${label}.package-dumpsys.txt" 2>&1 || true
  adb_target shell ps -A > "${RESULT_DIR}/${label}.ps-A.txt" 2>&1 || true
  adb_target shell cat /proc/net/dev \
    > "${RESULT_DIR}/${label}.proc-net-dev.txt" 2>&1 || true
  adb_target shell cat /proc/net/unix \
    > "${RESULT_DIR}/${label}.proc-net-unix.txt" 2>&1 || true
  adb_target shell dumpsys connectivity \
    > "${RESULT_DIR}/${label}.connectivity.txt" 2>&1 || true
  {
    if grep -Eq "(^|[[:space:]])${PACKAGE}([[:space:]]|$)" \
        "${RESULT_DIR}/${label}.ps-A.txt"; then
      printf 'runtime_process=present\n'
    else
      printf 'runtime_process=absent\n'
    fi
    if grep -Eq 'libvpp_runtime[.]so|vpp_runtime' \
        "${RESULT_DIR}/${label}.ps-A.txt"; then
      printf 'vpp_process=present\n'
    else
      printf 'vpp_process=absent\n'
    fi
    if grep -Eq '(^|[[:space:]])tun0:' \
        "${RESULT_DIR}/${label}.proc-net-dev.txt"; then
      printf 'tun0=present\n'
    else
      printf 'tun0=absent\n'
    fi
    if grep -Fq "VPN:${PACKAGE}" "${RESULT_DIR}/${label}.connectivity.txt"; then
      printf 'vpn_agent=present\n'
    else
      printf 'vpn_agent=absent\n'
    fi
    if remote_file_exists "$ROOT_API_SOCKET_PATH"; then
      printf 'root_api_socket=present\n'
    else
      printf 'root_api_socket=absent\n'
    fi
    if remote_file_exists "$POLICY_FENCE_PATH"; then
      printf 'policy_fence=present\n'
    else
      printf 'policy_fence=absent\n'
    fi
    if remote_file_exists "$POLICY_CANDIDATE_PATH"; then
      printf 'policy_candidate=present\n'
    else
      printf 'policy_candidate=absent\n'
    fi
    if remote_file_exists "$ROOT_OWNER_PATH"; then
      printf 'root_owner=present\n'
    else
      printf 'root_owner=absent\n'
    fi
  } > "${RESULT_DIR}/${label}.remote-paths.properties"
  cp -f "${RESULT_DIR}/${label}.remote-paths.properties" \
    "${RESULT_DIR}/${label}.residue-checks.properties"
}

current_generation() {
  local state="${RESULT_DIR}/current-state.properties"
  capture_remote_file "$STATE_PATH" "$state"
  local generation
  generation="$(property_value "$state" generation || true)"
  if [[ "$generation" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$generation"
  else
    printf '0\n'
  fi
}

wait_for_running() {
  local label="$1"
  local minimum_generation="$2"
  local output="${RESULT_DIR}/${label}.runtime-state.properties"
  local attempt
  local generation
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    capture_remote_file "$STATE_PATH" "$output"
    if grep -Fxq 'state=running' "$output" \
        && grep -Fxq 'profile=root' "$output" \
        && grep -Fxq 'adapterReadiness=root-nfqueue-tcp-udp-echo-dualstack-q2w2' "$output" \
        && grep -Fxq 'coreHealth=ok' "$output" \
        && grep -Fxq 'mayBeActive=true' "$output"; then
      generation="$(property_value "$output" generation || true)"
      if [[ "$generation" =~ ^[0-9]+$ ]] \
          && (( generation > minimum_generation )); then
        kv "${label}.generation" "$generation"
        return 0
      fi
    fi
    if grep -Fxq 'errorCode=root_authorization_required' "$output"; then
      fail_closed "Root start requires KernelSU Superuser grant for $PACKAGE"
    fi
    if grep -Fxq 'errorCode=notification_permission_required' "$output"; then
      fail_closed "Root start requires POST_NOTIFICATIONS permission"
    fi
    sleep 0.5
  done
  return 1
}

wait_for_stopped() {
  local label="$1"
  local output="${RESULT_DIR}/${label}.runtime-state.properties"
  local attempt
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    capture_remote_file "$STATE_PATH" "$output"
    if grep -Fxq 'state=stopped' "$output" \
        && grep -Fxq 'mayBeActive=false' "$output"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_fault_arm() {
  local output="${RESULT_DIR}/arm.policy-mutation-fault.properties"
  local expected_mode="$1"
  local minimum_generation="$2"
  local attempt
  local generation
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    capture_remote_file "$FAULT_STATUS_PATH" "$output"
    if grep -Fxq "mode=${expected_mode}" "$output" \
        && grep -Fxq 'armed=true' "$output" \
        && grep -Fxq 'operation_status_code=0' "$output"; then
      generation="$(property_value "$output" generation || true)"
      if [[ "$generation" =~ ^[0-9]+$ ]] \
          && (( generation == minimum_generation )); then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

wait_for_s194_status() {
  local label="$1"
  local expected_error_code="$2"
  local expected_operation_code="$3"
  local expected_state="$4"
  local minimum_generation="$5"
  local output="${RESULT_DIR}/${label}.s194-product-mutation.properties"
  local poll="${RESULT_DIR}/${label}.poll.tsv"
  local attempt
  local generation
  : > "$poll"
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    capture_remote_file "$S194_STATUS_PATH" "$output"
    generation="$(property_value "$output" generation || true)"
    printf '%s\t%s\t%s\t%s\t%s\n' \
      "$attempt" "$(date +%s)" "${generation:-missing}" \
      "$(property_value "$output" errorCode || true)" \
      "$(property_value "$output" operation_status_code || true)" >> "$poll"
    if grep -Fxq "state=${expected_state}" "$output" \
        && grep -Fxq "errorCode=${expected_error_code}" "$output" \
        && grep -Fxq "operation_status_code=${expected_operation_code}" "$output" \
        && [[ "$generation" =~ ^[0-9]+$ ]] \
        && (( generation >= minimum_generation )); then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

send_typed_l4_rule() {
  local destination_port="$1"
  local order="$2"
  start_activity \
    --es debugSetL4RuleSubject "$subject" \
    --es debugSetL4RuleFamily ipv4 \
    --es debugSetL4RuleSourceCidr 0.0.0.0/0 \
    --es debugSetL4RuleDestinationCidr 192.168.4.5/32 \
    --ei debugSetL4RuleSourcePortFirst 0 \
    --ei debugSetL4RuleSourcePortLast 65535 \
    --ei debugSetL4RuleDestinationPortFirst "$destination_port" \
    --ei debugSetL4RuleDestinationPortLast "$destination_port" \
    --ei debugSetL4RuleIpProtocol 6 \
    --es debugSetL4RuleDirection output \
    --es debugSetL4RuleNetworkContext wifi \
    --es debugSetL4RuleAction drop \
    --ei debugSetL4RulePriority 10 \
    --ei debugSetL4RuleOrder "$order"
}

validate_unknown_status() {
  local file="$1"
  grep -Fxq 'schema=s194-product-mutation/v1' "$file" \
    && grep -Fxq 'state=error' "$file" \
    && grep -Fxq 'errorCode=product_policy_outcome_unknown' "$file" \
    && grep -Fxq 'operation_status_code=14' "$file" \
    && grep -Fxq 'reconcile_readback_only=false' "$file" \
    && grep -Fxq 'reconcile_no_replay=false' "$file" \
    && grep -Eiq 'callback[^=]*not invoked' "$file"
}

validate_definite_status() {
  local file="$1"
  grep -Fxq 'schema=s194-product-mutation/v1' "$file" \
    && grep -Fxq 'stage=apply_failed' "$file" \
    && grep -Fxq 'state=error' "$file" \
    && grep -Fxq 'errorCode=product_policy_apply_failed' "$file" \
    && grep -Fxq 'operation_status_code=13' "$file" \
    && grep -Fxq 'reconcile_readback_only=false' "$file" \
    && grep -Fxq 'reconcile_no_replay=false' "$file" \
    && grep -Eiq 'not submitted' "$file"
}

validate_retry_bundle() {
  local file="$1"
  local expected_subject="$2"
  local expected_port="$3"
  python3 - "$file" "$expected_subject" "$expected_port" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_subject = sys.argv[2]
expected_port = int(sys.argv[3])
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

if props.get("schema") != "sakamoto-policy-bundle/v1":
    raise SystemExit("retry did not leave a canonical Product policy bundle")
try:
    count = int(props.get("l4RuleCount", "0"))
except ValueError as error:
    raise SystemExit("retry bundle l4RuleCount is not numeric") from error
if count <= 0:
    raise SystemExit("retry bundle has no typed L4 rule")
for index in range(count):
    prefix = f"l4.{index}."
    if (props.get(prefix + "subjectUid") == expected_subject
            and props.get(prefix + "ipFamily") == "4"
            and props.get(prefix + "ipProtocol") == "6"
            and props.get(prefix + "direction") == "3"
            and props.get(prefix + "action") == "2"
            and props.get(prefix + "networkContext", "1") in ("1", "3")
            and props.get(prefix + "destinationPortFirst") == str(expected_port)
            and props.get(prefix + "destinationPortLast") == str(expected_port)
            and props.get(prefix + "enabled") == "1"):
        raise SystemExit(0)
raise SystemExit("retry bundle does not contain the requested typed L4 rule")
PY
}

wait_for_retry_bundle() {
  local output="$1"
  local expected_subject="$2"
  local expected_port="$3"
  local attempt
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    # RuntimeService publishes the success status and canonical bundle in
    # separate durable writes.  Poll the bundle so the evidence capture does
    # not race that publication boundary.
    capture_remote_file "$POLICY_BUNDLE_PATH" "$output"
    if validate_retry_bundle "$output" "$expected_subject" "$expected_port"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

validate_no_mutation_residue() {
  ! remote_file_exists "$POLICY_FENCE_PATH" \
    && ! remote_file_exists "$POLICY_CANDIDATE_PATH"
}

record_generation_evidence() {
  local label="$1"
  local state_file="${RESULT_DIR}/${label}.runtime-state.properties"
  local owner_file="${RESULT_DIR}/${label}.root-owner.properties"
  local generation="$(property_value "$state_file" generation || true)"
  local handle="$(property_value "$owner_file" token || true)"
  [[ -n "$handle" ]] || handle="unavailable"
  [[ -n "$generation" ]] || generation="unavailable"
  kv "${label}_generation" "$generation"
  kv "${label}_handle" "$handle"
}

validate_success_status() {
  local file="$1"
  grep -Fxq 'schema=s194-product-mutation/v1' "$file" \
    && grep -Fxq 'state=ok' "$file" \
    && grep -Fxq 'errorCode=' "$file" \
    && grep -Fxq 'operation_status_code=0' "$file" \
    && grep -Fxq 'reconcile_readback_only=false' "$file" \
    && grep -Fxq 'reconcile_no_replay=false' "$file"
}

validate_fenced_status() {
  local file="$1"
  grep -Fxq 'schema=s194-product-mutation/v1' "$file" \
    && grep -Fxq 'state=error' "$file" \
    && grep -Fxq 'errorCode=product_policy_mutation_fenced' "$file" \
    && grep -Fxq 'operation_status_code=15' "$file" \
    && grep -Eiq 'fenced until fresh-generation readback' "$file"
}

validate_fresh_status() {
  local file="$1"
  local minimum_generation="$2"
  python3 - "$file" "$minimum_generation" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
minimum_generation = int(sys.argv[2])
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

def need(key, expected=None):
    value = props.get(key, "")
    if expected is not None and value != expected:
        raise SystemExit(f"{key}={value!r}, expected {expected!r}")
    if expected is None and value == "":
        raise SystemExit(f"{key} is empty")
    return value

def number(key):
    try:
        return int(need(key))
    except ValueError as error:
        raise SystemExit(f"{key} is not numeric") from error

def truthy(key):
    if need(key).lower() not in ("true", "1"):
        raise SystemExit(f"{key} is not true")

need("schema", "s194-product-mutation/v1")
if not need("stage").startswith("startup_reconcile"):
    raise SystemExit(f"unexpected reconcile stage: {props.get('stage')!r}")
need("state", "ok")
need("errorCode", "")
generation = number("generation")
if generation <= minimum_generation:
    raise SystemExit(f"fresh generation {generation} is not newer than {minimum_generation}")
if number("policy_generation") != generation:
    raise SystemExit("policy generation does not match runtime generation")
if number("policy_requested_revision") <= 0:
    raise SystemExit("policy requested revision is not positive")
if number("policy_active_revision") != number("policy_requested_revision"):
    raise SystemExit("policy requested/active revision mismatch")
if number("policy_snapshot_hash") <= 0:
    raise SystemExit("policy snapshot hash is not positive")
for key in (
    "policy_snapshot_identity", "artifact_id", "api_identity", "vpp_revision",
):
    need(key)
truthy("policy_generation_match")
truthy("policy_artifact_match")
need("policy_mixed_revision", "false")
need("policy_last_apply_status_code", "0")
need("operation_status_code", "0")
need("reconcile_readback_only", "true")
need("reconcile_no_replay", "true")
PY
}

validate_final_residue() {
  local state="${RESULT_DIR}/final.runtime-state.properties"
  local processes="${RESULT_DIR}/final.ps-A.txt"
  local netdev="${RESULT_DIR}/final.proc-net-dev.txt"
  local connectivity="${RESULT_DIR}/final.connectivity.txt"
  grep -Fxq 'state=stopped' "$state" \
    && grep -Fxq 'mayBeActive=false' "$state" \
    && ! grep -Eq "(^|[[:space:]])${PACKAGE}([[:space:]]|$)" "$processes" \
    && ! grep -Eq 'libvpp_runtime[.]so|vpp_runtime' "$processes" \
    && ! grep -Eq '(^|[[:space:]])tun0:' "$netdev" \
    && ! grep -Fq "VPN:${PACKAGE}" "$connectivity" \
    && ! remote_file_exists "$ROOT_API_SOCKET_PATH" \
    && ! remote_path_exists "$ROOT_RUNTIME_DIR" \
    && ! remote_file_exists "$ROOT_OWNER_PATH" \
    && ! remote_file_exists "$POLICY_FENCE_PATH" \
    && ! remote_file_exists "$POLICY_CANDIDATE_PATH"
}

capture_apk_provenance() {
  if [[ -z "$apk" ]]; then
    kv apk not-provided
    return 0
  fi
  kv apk "$apk"
  sha256sum "$apk" | awk '{print $1}' > "${RESULT_DIR}/apk.sha256"
  kv apk_sha256 "$(tr -d '\r\n' < "${RESULT_DIR}/apk.sha256")"
  unzip -p "$apk" assets/product-stage.properties \
    > "${RESULT_DIR}/apk-product-stage.properties" 2> "${RESULT_DIR}/apk-stage.stderr" \
    || : > "${RESULT_DIR}/apk-product-stage.properties"
  if [[ -s "${RESULT_DIR}/apk-product-stage.properties" ]]; then
    kv apk_stage_manifest_present true
    kv apk_stage_api_identity \
      "$(property_value "${RESULT_DIR}/apk-product-stage.properties" apiIdentity || true)"
    kv apk_stage_artifact_id \
      "$(property_value "${RESULT_DIR}/apk-product-stage.properties" artifactId || true)"
    kv apk_stage_vpp_revision \
      "$(property_value "${RESULT_DIR}/apk-product-stage.properties" vppRevision || true)"
  else
    kv apk_stage_manifest_present false
  fi
  if unzip -p "$apk" lib/arm64-v8a/libproduct_core_plugin.so \
      > "${RESULT_DIR}/apk-libproduct_core_plugin.so" \
      2> "${RESULT_DIR}/apk-plugin.stderr"; then
    sha256sum "${RESULT_DIR}/apk-libproduct_core_plugin.so" \
      > "${RESULT_DIR}/apk-native-hashes.txt"
    strings "${RESULT_DIR}/apk-libproduct_core_plugin.so" \
      | rg -i 'product_core[.]api|vl_api_version|artifact|revision' \
      > "${RESULT_DIR}/apk-plugin-identity.strings" 2>/dev/null || true
  else
    printf 'libproduct_core_plugin.so=missing\n' \
      > "${RESULT_DIR}/apk-native-hashes.txt"
  fi
}

capture_artifact_provenance() {
  local apk_hash="not-provided"
  local stage_manifest=""
  local stage_hash="not-provided"
  local source_revision="unknown"
  if [[ -n "$apk" && -s "${RESULT_DIR}/apk.sha256" ]]; then
    apk_hash="$(tr -d '\r\n' < "${RESULT_DIR}/apk.sha256")"
  fi
  if [[ -n "$stage" ]]; then
    if [[ -f "$stage" ]]; then
      stage_manifest="$stage"
    elif [[ -f "$stage/product-stage.properties" ]]; then
      stage_manifest="$stage/product-stage.properties"
    fi
    if [[ -n "$stage_manifest" ]]; then
      cp -f "$stage_manifest" "${RESULT_DIR}/stage-product-stage.properties"
      stage_hash="$(sha256sum "$stage_manifest" | awk '{print $1}')"
    fi
  fi
  if [[ -d "$source_root/.git" || -f "$source_root/.git" ]]; then
    source_revision="$(git -C "$source_root" rev-parse HEAD 2>/dev/null || true)"
    [[ -n "$source_revision" ]] || source_revision="unknown"
  fi
  {
    printf 'apk_path=%s\n' "${apk:-not-provided}"
    printf 'apk_sha256=%s\n' "$apk_hash"
    printf 'stage_path=%s\n' "${stage:-not-provided}"
    printf 'stage_manifest=%s\n' "${stage_manifest:-not-found}"
    printf 'stage_manifest_sha256=%s\n' "$stage_hash"
    printf 'source=%s\n' "$source_root"
    printf 'source_revision=%s\n' "$source_revision"
    printf 'adb_wrapper=%s\n' "$ADB"
    printf 'adb_wrapper_relative=./dev/adb\n'
    printf 'serial=%s\n' "$serial"
    printf 'package=%s\n' "$PACKAGE"
    printf 'fault_mode=%s\n' "$fault_mode"
  } > "${RESULT_DIR}/artifact-provenance.txt"
  kv artifact_provenance "${RESULT_DIR}/artifact-provenance.txt"
  kv stage_path "${stage:-not-provided}"
  kv source "$source_root"
}

discover_installed_uid() {
  local package_list="${RESULT_DIR}/package-list.txt"
  local dumpsys="${RESULT_DIR}/package-dumpsys.txt"
  local uid=""
  adb_target shell cmd package list packages -U "$PACKAGE" \
    > "$package_list" 2> "${package_list}.stderr" || true
  uid="$(tr -d '\r' < "$package_list" | awk -v package="package:${PACKAGE}" \
    '$1 == package { for (i = 1; i <= NF; i++) {
       if ($i ~ /^uid:/) { sub(/^uid:/, "", $i); print $i; exit }
     }}')"
  if [[ -z "$uid" ]]; then
    uid="$(tr -d '\r' < "$RESULT_DIR/package-dumpsys.txt" \
      | awk -F= '/userId=/{ gsub(/[^0-9].*/, "", $2); print $2; exit }')"
  fi
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || (( uid <= 0 )); then
    fail_closed "could not discover installed UID for $PACKAGE"
  fi
  printf '%s\n' "$uid"
}

cleanup() {
  local status=$?
  local lock_released=false
  set +e
  if [[ "$run_lock_acquired" == 1 ]]; then
    if [[ "$runtime_started" == 1 ]]; then
      start_activity --ez runtimeStop true >/dev/null 2>&1 || true
      wait_for_stopped cleanup >/dev/null 2>&1 || true
      runtime_started=0
    fi
    adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
    sleep 1
    capture_phase final
    capture_device_snapshot final
    if validate_final_residue; then
      kv cleanup_final_residue_clean true
    else
      kv cleanup_final_residue_clean false
    fi
    if [[ -d "$RUN_LOCK_DIR" ]]; then
      kv final_lock_present_before_release true
    else
      kv final_lock_present_before_release false
    fi
    rm -f "${RUN_LOCK_DIR}/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
    if [[ ! -d "$RUN_LOCK_DIR" ]]; then
      lock_released=true
    fi
  else
    kv final_device_cleanup_skipped true
  fi
  if [[ "$acceptance_complete" == 1 && "$status" == 0 ]]; then
    kv final_lock_released "$lock_released"
    if [[ "$lock_released" == true ]]; then
      kv result PASS
      echo "SAKAMOTO-194 typed product mutation: PASS"
    else
      status=1
      failure_recorded=1
      kv result FAIL
      kv failure "S194 run lock was not released: ${RUN_LOCK_DIR}"
    fi
  else
    kv final_lock_released "$lock_released"
    if [[ "$status" != 0 && "$failure_recorded" == 0 ]]; then
      failure_recorded=1
      kv result FAIL
      kv failure "runner exited with status ${status}"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

kv test_id SAKAMOTO-194-product-mutation
kv serial "$serial"
kv package "$PACKAGE"
kv activity "$ACTIVITY"
kv adb_wrapper "./dev/adb"
kv result_dir "$RESULT_DIR"
kv install_apk "$install_apk"
kv fault_mode "$fault_mode"
capture_apk_provenance
capture_artifact_provenance

acquire_run_lock
adb_raw devices > "${RESULT_DIR}/adb-devices.txt" \
  2> "${RESULT_DIR}/adb-devices.stderr" \
  || fail_closed "./dev/adb devices failed"
if ! tr -d '\r' < "${RESULT_DIR}/adb-devices.txt" \
    | awk -v serial="$serial" \
      'NR > 1 && $1 == serial && $2 == "device" { found = 1 }
       END { exit found ? 0 : 1 }'; then
  fail_closed "controlled serial is not an online device through ./dev/adb"
fi
kv adb_devices_contains_serial true
adb_target get-state > "${RESULT_DIR}/adb-get-state.txt" \
  || fail_closed "./dev/adb get-state failed"
kv adb_get_state "$(tr -d '\r\n' < "${RESULT_DIR}/adb-get-state.txt")"
adb_target shell getprop ro.product.model \
  > "${RESULT_DIR}/device-model.txt" 2>&1 \
  || fail_closed "could not read device model"
if ! grep -Fq 'Pixel 6a' "${RESULT_DIR}/device-model.txt"; then
  fail_closed "connected serial is not the controlled Pixel 6a"
fi

if [[ "$install_apk" == 1 ]]; then
  adb_target install -r -d "$apk" \
    > "${RESULT_DIR}/install.log" 2>&1 \
    || fail_closed "APK install failed; see ${RESULT_DIR}/install.log"
  kv apk_install_result PASS
fi
adb_target shell pm path "$PACKAGE" \
  > "${RESULT_DIR}/package-path.txt" 2>&1 \
  || fail_closed "installed APK is missing: $PACKAGE"
adb_target shell pm enable --user 0 "$PACKAGE" \
  > "${RESULT_DIR}/package-enable.log" 2>&1 || true
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  > "${RESULT_DIR}/notification-grant.log" 2>&1 || true
adb_target shell dumpsys package "$PACKAGE" \
  > "${RESULT_DIR}/package-dumpsys.txt" 2>&1 \
  || fail_closed "could not read package dumpsys"
app_uid="$(discover_installed_uid)"
subject="android.uid:${app_uid}"
kv installed_app_uid "$app_uid"
kv installed_app_uid_complete true
kv policy_subject "$subject"
if [[ "$app_uid" != "$EXPECTED_UID" ]]; then
  fail_closed "installed UID $app_uid differs from expected controlled UID $EXPECTED_UID"
fi

# Stop and settle before examining durable mutation state.  An unresolved
# fence/candidate is a precondition failure, not something the runner may
# delete: doing so would erase the very uncertainty S194 is testing.
start_activity --ez runtimeStop true >/dev/null 2>&1 || true
wait_for_stopped preflight >/dev/null 2>&1 || true
adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
sleep 1
capture_phase preflight
capture_device_snapshot preflight
if remote_file_exists "$POLICY_FENCE_PATH" \
    || remote_file_exists "$POLICY_CANDIDATE_PATH"; then
  fail_closed "preflight has unresolved policy mutation fence/candidate; see preflight evidence"
fi
clear_remote_file "$S194_STATUS_PATH"
clear_remote_file "$FAULT_STATUS_PATH"
kv preflight_unresolved_mutation false

before_generation="$(current_generation)"
start_activity --ez runtimeStart true --es runtimeProfile root \
  || fail_closed "Root runtime start command failed"
runtime_started=1
if ! wait_for_running root-start "$before_generation"; then
  capture_phase root-start-failure
  capture_device_snapshot root-start-failure
  fail_closed "Root Product Core did not reach running/root-nfqueue"
fi
capture_phase root-start
capture_device_snapshot root-start
root_generation="$(property_value "${RESULT_DIR}/root-start.runtime-state.properties" generation)"
root_handle="$(property_value "${RESULT_DIR}/root-start.root-owner.properties" token || true)"
[[ -n "$root_handle" ]] || root_handle="unavailable"
record_generation_evidence root-start
kv root_generation "$root_generation"
kv root_handle "$root_handle"
kv old_generation "$root_generation"
kv old_handle "$root_handle"

start_activity --es runtimePolicyMutationFaultMode "$fault_mode" \
  || fail_closed "could not issue Product mutation fault arm command"
if ! wait_for_fault_arm "$fault_mode" "$root_generation"; then
  capture_phase arm-failure
  fail_closed "${fault_mode} fault was not armed on the active generation"
fi
capture_phase arm
kv fault_mode "$fault_mode"
kv fault_armed true

# Send one complete, explicit typed L4 rule.  No probe is needed: S194 tests
# the policy mutation transport boundary and its durable recovery hand-off.
send_typed_l4_rule 19400 0 \
  || fail_closed "typed mutation command failed"

if [[ "$fault_mode" == "bundle_pre_submit_not_sent" ]]; then
  if ! wait_for_s194_status pre-submit-apply \
      product_policy_apply_failed 13 error "$root_generation"; then
    capture_phase pre-submit-apply-timeout
    fail_closed "pre-submit mutation did not publish definite apply-failed status"
  fi
  capture_phase pre-submit-apply
  capture_device_snapshot pre-submit-apply
  if ! validate_definite_status \
      "${RESULT_DIR}/pre-submit-apply.s194-product-mutation.properties"; then
    fail_closed "pre-submit definite-failure status fields are invalid"
  fi
  if remote_file_exists "$POLICY_FENCE_PATH" \
      || remote_file_exists "$POLICY_CANDIDATE_PATH"; then
    fail_closed "pre-submit definite failure unexpectedly retained fence/candidate"
  fi
  kv pre_submit_status PASS
  kv pre_submit_old_generation "$root_generation"
  kv pre_submit_old_handle "$root_handle"
  kv pre_submit_operation_status_code 13
  kv pre_submit_vapi_submission false
  kv pre_submit_fence_present false
  kv pre_submit_candidate_present false

  # The fault is one-shot. Retry the same successor explicitly and require
  # successful status plus durable canonical typed-L4 publication.
  clear_remote_file "$S194_STATUS_PATH"
  send_typed_l4_rule 19400 0 \
    || fail_closed "explicit pre-submit retry command failed"
  if ! wait_for_s194_status pre-submit-retry "" 0 ok "$root_generation"; then
    capture_phase pre-submit-retry-timeout
    fail_closed "explicit pre-submit retry did not publish successful status"
  fi
  capture_phase pre-submit-retry
  capture_device_snapshot pre-submit-retry
  if ! validate_success_status \
      "${RESULT_DIR}/pre-submit-retry.s194-product-mutation.properties"; then
    fail_closed "explicit pre-submit retry status or typed bundle fields are invalid"
  fi
  if ! wait_for_retry_bundle \
      "${RESULT_DIR}/pre-submit-retry.policy-bundle.properties" \
      "$app_uid" 19400; then
    fail_closed "explicit pre-submit retry status or typed bundle fields are invalid"
  fi
  if remote_file_exists "$POLICY_FENCE_PATH" \
      || remote_file_exists "$POLICY_CANDIDATE_PATH"; then
    fail_closed "explicit pre-submit retry retained an unexpected fence/candidate"
  fi
  kv pre_submit_explicit_retry true
  kv pre_submit_retry_gate_entry_count \
    "$(property_value "${RESULT_DIR}/pre-submit-retry.policy-bundle.properties" \
        gateEntryCount)"
  kv pre_submit_retry_bundle_published true
  kv pre_submit_retry_fence_present false
  kv pre_submit_retry_candidate_present false
  kv reconcile_not_required true
  kv new_generation not-applicable
  kv new_handle not-applicable
  kv pre_submit_new_generation not-applicable
  kv pre_submit_new_handle not-applicable
  # There is no ambiguous operation here, so no-replay is not applicable.
  kv no_replay_applicable true
else
if ! wait_for_s194_status unknown-apply \
    product_policy_outcome_unknown 14 error "$root_generation"; then
  capture_phase unknown-apply-timeout
  fail_closed "typed mutation did not publish outcome-unknown status"
fi
capture_phase unknown-apply
capture_device_snapshot unknown-apply
if ! validate_unknown_status \
    "${RESULT_DIR}/unknown-apply.s194-product-mutation.properties"; then
  fail_closed "outcome-unknown status fields are invalid"
fi
if ! remote_file_exists "$POLICY_FENCE_PATH" \
    || ! remote_file_exists "$POLICY_CANDIDATE_PATH"; then
  fail_closed "unknown mutation did not retain both durable fence and candidate"
fi
kv unknown_apply_status PASS
kv unknown_apply_operation_status_code 14
kv unknown_apply_fence_present true
kv unknown_apply_candidate_present true

# A second typed mutation on this same generation must be rejected before any
# second VAPI submission.  The changed destination port makes accidental
# persistence/replay visible in the retained policy evidence.
clear_remote_file "$S194_STATUS_PATH"
send_typed_l4_rule 19401 1 \
  || fail_closed "same-generation fenced mutation command failed"
if ! wait_for_s194_status fenced-reapply \
    product_policy_mutation_fenced 15 error "$root_generation"; then
  capture_phase fenced-reapply-timeout
  fail_closed "same-generation mutation did not publish fenced status"
fi
capture_phase fenced-reapply
capture_device_snapshot fenced-reapply
if ! validate_fenced_status \
    "${RESULT_DIR}/fenced-reapply.s194-product-mutation.properties"; then
  fail_closed "mutation-fenced status fields are invalid"
fi
if ! remote_file_exists "$POLICY_FENCE_PATH" \
    || ! remote_file_exists "$POLICY_CANDIDATE_PATH"; then
  fail_closed "fenced mutation unexpectedly changed durable fence/candidate state"
fi
kv fenced_reapply_status PASS
kv fenced_reapply_operation_status_code 15
kv fenced_reapply_blocked true
kv dependent_mutation_blocked true
kv fenced_reapply_no_second_vapi true

start_activity --ez runtimeStop true \
  || fail_closed "runtime stop command failed before fresh reconcile"
if ! wait_for_stopped before-fresh-reconcile; then
  capture_phase stop-failure
  fail_closed "runtime did not stop before fresh-generation reconcile"
fi
runtime_started=0
capture_phase stopped-before-fresh
old_generation="$root_generation"
kv callback_old_generation "$old_generation"
kv callback_old_handle "$root_handle"
start_activity --ez runtimeStart true --es runtimeProfile root \
  || fail_closed "fresh Root runtime start command failed"
runtime_started=1
if ! wait_for_running fresh-start "$old_generation"; then
  capture_phase fresh-start-failure
  capture_device_snapshot fresh-start-failure
  fail_closed "fresh Root Product Core did not reach running/root-nfqueue"
fi
capture_phase fresh-start
capture_device_snapshot fresh-start
fresh_generation="$(property_value "${RESULT_DIR}/fresh-start.runtime-state.properties" generation)"
record_generation_evidence fresh-start
fresh_handle="$(property_value "${RESULT_DIR}/fresh-start.root-owner.properties" token || true)"
[[ -n "$fresh_handle" ]] || fresh_handle="unavailable"
kv fresh_generation "$fresh_generation"
kv new_generation "$fresh_generation"
kv new_handle "$fresh_handle"
kv callback_new_generation "$fresh_generation"
kv callback_new_handle "$fresh_handle"
if [[ "$fresh_generation" =~ ^[0-9]+$ && "$old_generation" =~ ^[0-9]+$ ]] \
    && (( fresh_generation > old_generation )); then
  kv callback_generation_changed true
else
  fail_closed "fresh callback generation did not advance beyond fenced generation"
fi
if ! wait_for_s194_status fresh-reconcile "" 0 ok "$old_generation"; then
  capture_phase fresh-reconcile-timeout
  fail_closed "fresh generation did not publish S194 reconcile status"
fi
capture_phase fresh-reconcile
if ! validate_fresh_status \
    "${RESULT_DIR}/fresh-reconcile.s194-product-mutation.properties" \
    "$old_generation"; then
  fail_closed "fresh-generation S194 readback status is invalid"
fi
if ! grep -Eiq 'unknown policy mutation (reconciled|discarded)' \
    "${RESULT_DIR}/fresh-reconcile.runtime-service.log"; then
  fail_closed "runtime log lacks explicit readback-only mutation resolution"
fi
if remote_file_exists "$POLICY_FENCE_PATH" \
    || remote_file_exists "$POLICY_CANDIDATE_PATH"; then
  fail_closed "fresh reconcile left durable fence/candidate residue"
fi
kv fresh_reconcile_status PASS
kv fresh_reconcile_readback_only true
kv fresh_reconcile_no_replay true
kv fresh_reconcile_generation_changed true
fi

start_activity --ez runtimeStop true \
  || fail_closed "final runtime stop command failed"
if ! wait_for_stopped final-stop; then
  capture_phase final-stop-failure
  fail_closed "final runtime stop did not report mayBeActive=false"
fi
runtime_started=0
adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
sleep 1
capture_phase final
capture_device_snapshot final
if ! validate_final_residue; then
  fail_closed "final runtime/VPP/socket/TUN/VPN residue is not clean"
fi
kv final_residue_clean true
kv final_residue_real_check true
acceptance_complete=1
exit 0
