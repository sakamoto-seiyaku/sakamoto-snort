#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-189 Root Network Gate real-device acceptance.
#
# PASS means the installed debug APK on the controlled Pixel 6a starts the
# Root Product Core, discovers the APK complete Linux UID, clears any old
# runtime policy to an empty default-pass baseline, proves real APK TCP traffic
# reaches a Controlled LAN echo server, applies one Wi-Fi Network Gate block
# through ProductBackend -> Rust Product Core -> VAPI -> VPP, proves the same
# APK traffic is dropped through physical Root NFQUEUE with revision/rule/reason
# evidence, then applies the successor open rule and proves traffic restores.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S189_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s189-root-network-gate}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s189-device-run.lock"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly S188_STATUS_PATH="files/product-state/s188-empty-policy-snapshot.properties"
readonly S189_STATUS_PATH="files/product-state/s189-root-network-gate.properties"
readonly GATE_STORE_PATH="files/product-policy/policy-bundle.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly EMPTY_STORE_PATH="files/product-policy/empty-intent.properties"
readonly POLICY_BUNDLE_PATH="files/product-policy/policy-bundle.properties"
readonly L4_STORE_PATH="files/product-policy/l4-intent.properties"
readonly TRAFFIC_PROBE_PATH="files/debug/traffic-probe.properties"
readonly S189_WAIT_ATTEMPTS="${S189_WAIT_ATTEMPTS:-240}"
readonly S189_ADB_COMMAND_TIMEOUT_SECONDS="${S189_ADB_COMMAND_TIMEOUT_SECONDS:-20}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s189-root-network-gate-product.sh --run --host <controlled-lan-ipv4>

Required:
  --run
  --host / S189_CONTROLLED_LAN_HOST

Optional:
  --serial 28201JEGR0XPAJ
  --port / S189_TCP4_PORT             default 18989
  --timeout-ms / S189_TIMEOUT_MILLIS  default 5000

Before running, install the debug APK, approve it as an Android VPN service if
prompted by prior runs, and grant the app Superuser in KernelSU Manager. ADB
shell root alone is not accepted as Product root authorization.

Required final evidence:
  installed_app_uid_complete=true
  baseline_traffic=tcp_echo_matched
  gate_blocked=true
  blocked_traffic=tcp_connect_failed
  policy_drop_recorded=true
  physical_nfqueue_completion=true
  policy_last_drop_verdict=2
  policy_last_drop_winner=1
  policy_last_drop_device_direction=OUTPUT
  gate_open=true
  open_restore_traffic=tcp_echo_matched
EOF
}

serial="$S189_SERIAL"
run=0
controlled_host="${S189_CONTROLLED_LAN_HOST:-}"
port="${S189_TCP4_PORT:-18989}"
timeout_ms="${S189_TIMEOUT_MILLIS:-5000}"
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

if [[ "$serial" != "$S189_SERIAL" ]]; then
  echo "SAKAMOTO-189 only accepts controlled Pixel 6a serial $S189_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S189_CONTROLLED_LAN_HOST" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Controlled LAN host must be an IPv4 literal: $controlled_host" >&2
  exit 2
fi
if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
  echo "invalid TCP4 port: $port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
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
  echo "SAKAMOTO-189 FAIL: $1" >&2
  exit 1
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if timeout "$S189_ADB_COMMAND_TIMEOUT_SECONDS" "$ADB" "$@"; then
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

clear_product_policy_files() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" \
    "$S188_STATUS_PATH" \
    "$S189_STATUS_PATH" \
    "$PRODUCT_STATE_PATH" \
    "$PRODUCT_TRANSACTIONS_PATH" \
    "$EMPTY_STORE_PATH" \
    "$GATE_STORE_PATH" \
    "$POLICY_BUNDLE_PATH" \
    "$L4_STORE_PATH" \
    "$TRAFFIC_PROBE_PATH" >/dev/null 2>&1 || true
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
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
    if [[ "$lock_args" == *"s189-root-network-gate-product.sh"* ]]; then
      fail_closed "another S189 runner is active: pid=$lock_pid"
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
  fail_closed "could not acquire S189 device run lock"
}

property_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' "$file"
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
  for attempt in $(seq 1 "$S189_WAIT_ATTEMPTS"); do
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
  for attempt in $(seq 1 "$S189_WAIT_ATTEMPTS"); do
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
  for attempt in $(seq 1 "$S189_WAIT_ATTEMPTS"); do
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

validate_s189_status_file() {
  local file="$1"
  local expected_stage="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_blocked="$5"
  local min_revision="$6"
  local require_drop="$7"
  python3 - "$file" "$expected_stage" "$expected_uid" "$expected_context" \
    "$expected_blocked" "$min_revision" "$require_drop" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_stage = sys.argv[2]
expected_uid = int(sys.argv[3])
expected_context = int(sys.argv[4])
expected_blocked = sys.argv[5].lower() == "true"
min_revision = int(sys.argv[6])
require_drop = sys.argv[7].lower() == "true"
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

need("schema", "s189-root-network-gate/v1")
if expected_stage != "-":
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
truthy("gate_snapshot")
falsey("policy_snapshot_empty")
falsey("ui_policy_authority")
falsey("vpp_policy_authority")
if number("gate_subject_uid") != expected_uid:
    raise SystemExit("gate_subject_uid mismatch")
if number("gate_network_context") != expected_context:
    raise SystemExit("gate_network_context mismatch")
actual_blocked = need("gate_blocked").lower() in ("1", "true")
if actual_blocked != expected_blocked:
    raise SystemExit("gate_blocked mismatch")
expected_claims = 1 if expected_blocked else 0
if number("gate_claim_count") != expected_claims:
    raise SystemExit("gate_claim_count mismatch")
if number("l4_rule_count") != 0:
    raise SystemExit("l4_rule_count must be zero")
rule_id = number("gate_rule_id")
reason_id = number("gate_reason_id")
if rule_id <= 0 or reason_id <= 0:
    raise SystemExit("gate rule/reason missing")
if need("rust_product_store") != "product-policy/policy-bundle.properties":
    raise SystemExit("complete policy bundle is not authoritative")
truthy("rust_product_store_single_writer")
if require_drop:
    truthy("policy_drop_recorded")
    truthy("physical_nfqueue_completion")
    if number("policy_last_drop_uid") != expected_uid:
        raise SystemExit("policy_last_drop_uid mismatch")
    if number("policy_last_drop_network_context") != expected_context:
        raise SystemExit("policy_last_drop_network_context mismatch")
    if number("policy_last_drop_revision") != active:
        raise SystemExit("policy_last_drop_revision mismatch")
    if number("policy_last_drop_rule_id") != rule_id:
        raise SystemExit("policy_last_drop_rule_id mismatch")
    if number("policy_last_drop_reason_id") != reason_id:
        raise SystemExit("policy_last_drop_reason_id mismatch")
    if number("policy_last_drop_completion_attempts") != 1:
        raise SystemExit("policy_last_drop_completion_attempts mismatch")
    need("policy_last_drop_verdict", "2")
    need("policy_last_drop_winner", "1")
    truthy("policy_last_drop_uid_known")
    need("policy_last_drop_device_direction", "OUTPUT")
    need("expected_policy_last_drop_verdict", "2")
    need("expected_policy_last_drop_winner", "1")
    need("expected_policy_last_drop_device_direction", "3")
print(f"active_revision={active}")
print(f"gate_rule_id={rule_id}")
print(f"gate_reason_id={reason_id}")
print(f"gate_blocked={str(expected_blocked).lower()}")
if require_drop:
    print(f"policy_drop_records={number('policy_drop_records')}")
    print("policy_drop_recorded=true")
    print("physical_nfqueue_completion=true")
    print("policy_last_drop_verdict=2")
    print("policy_last_drop_winner=1")
    print("policy_last_drop_device_direction=OUTPUT")
PY
}

capture_s189_status() {
  local label="$1"
  local expected_stage="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_blocked="$5"
  local min_revision="$6"
  local require_drop="$7"
  local output="$RESULT_DIR/${label}.s189.properties"
  local values="$RESULT_DIR/${label}.s189.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S189_WAIT_ATTEMPTS"); do
    read_app_file "$S189_STATUS_PATH" > "$output"
    if validate_s189_status_file "$output" "$expected_stage" "$expected_uid" \
        "$expected_context" "$expected_blocked" "$min_revision" "$require_drop" \
        > "$values" 2>"$RESULT_DIR/${label}.s189.validation.stderr"; then
      while IFS= read -r line; do
        kv "${label}.${line%%=*}" "${line#*=}"
      done < "$values"
      kv "${label}.status_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} S189 status did not become valid; see ${output}"
}

validate_gate_store_matches() {
  local label="$1"
  local expected_revision="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_blocked="$5"
  local expected_rule_id="$6"
  local expected_reason_id="$7"
  local store_file="$RESULT_DIR/${label}.policy-bundle.properties"
  read_app_file "$GATE_STORE_PATH" > "$store_file"
  python3 - "$store_file" "$expected_revision" "$expected_uid" "$expected_context" \
    "$expected_blocked" "$expected_rule_id" "$expected_reason_id" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_action = "2" if sys.argv[5] == "true" else "1"
expected = {
    "schema": "sakamoto-policy-bundle/v1",
    "abiVersion": "1",
    "revision": sys.argv[2],
    "gateEntryCount": "1",
    "l4RuleCount": "0",
    "defaultPass": "1",
    "snapshotIdentity": "sakamoto-policy-bundle/v1",
    "gate.0.subjectUid": sys.argv[3],
    "gate.0.networkContext": sys.argv[4],
    "gate.0.ruleKind": "1",
    "gate.0.action": expected_action,
    "gate.0.enabled": "1",
    "gate.0.ruleId": sys.argv[6],
    "gate.0.reasonId": sys.argv[7],
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
  for attempt in $(seq 1 "$S189_WAIT_ATTEMPTS"); do
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
  local nonce="$2"
  local expected_probe="$3"
  local expected_server="$4"
  local uid="$5"
  local ready_file="$RESULT_DIR/${label}.tcp4.ready"
  local server_log="$RESULT_DIR/${label}.tcp4.server.log"
  local timeout_seconds=$(((timeout_ms + 1999) / 1000))
  if (( timeout_seconds < 2 )); then
    timeout_seconds=2
  fi

  rm -f "$ready_file" "$server_log"
  start_tcp4_echo_server_once "0.0.0.0" "$port" "$nonce" "$ready_file" \
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
    --ei debugTrafficPort "$port" \
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

kv acceptance SAKAMOTO-189-root-network-gate
kv serial "$serial"
kv package "$PACKAGE"
kv host "$controlled_host"
kv port "$port"
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
clear_product_policy_files

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_running_root

start_activity --ez debugApplyEmptyPolicy true
wait_for_s188_empty

baseline_nonce="s189-baseline-${RUN_ID}"
run_app_tcp_probe_with_server baseline "$baseline_nonce" tcp_echo_matched \
  tcp_echo_matched "$app_uid"
kv baseline_traffic tcp_echo_matched

clear_app_file "$S189_STATUS_PATH"
start_activity --es debugSetNetworkGateSubject "$subject" \
  --es debugSetNetworkGateContext wifi \
  --ez debugSetNetworkGateBlocked true
capture_s189_status gate_blocked gate_blocked "$app_uid" 1 true 0 false
block_revision="$(property_value "$RESULT_DIR/gate_blocked.s189.summary-fragment.properties" active_revision)"
block_rule_id="$(property_value "$RESULT_DIR/gate_blocked.s189.summary-fragment.properties" gate_rule_id)"
block_reason_id="$(property_value "$RESULT_DIR/gate_blocked.s189.summary-fragment.properties" gate_reason_id)"
validate_gate_store_matches gate_blocked "$block_revision" "$app_uid" 1 true \
  "$block_rule_id" "$block_reason_id"
kv gate_blocked true

blocked_nonce="s189-blocked-${RUN_ID}"
run_app_tcp_probe_with_server blocked "$blocked_nonce" tcp_connect_failed \
  tcp_echo_unseen "$app_uid"
kv blocked_traffic tcp_connect_failed

start_activity --ez debugRefresh true
capture_s189_status gate_drop - "$app_uid" 1 true $((block_revision - 1)) true

clear_app_file "$S189_STATUS_PATH"
start_activity --es debugSetNetworkGateSubject "$subject" \
  --es debugSetNetworkGateContext wifi \
  --ez debugSetNetworkGateBlocked false
capture_s189_status gate_open gate_open "$app_uid" 1 false "$block_revision" false
open_revision="$(property_value "$RESULT_DIR/gate_open.s189.summary-fragment.properties" active_revision)"
open_rule_id="$(property_value "$RESULT_DIR/gate_open.s189.summary-fragment.properties" gate_rule_id)"
open_reason_id="$(property_value "$RESULT_DIR/gate_open.s189.summary-fragment.properties" gate_reason_id)"
validate_gate_store_matches gate_open "$open_revision" "$app_uid" 1 false \
  "$open_rule_id" "$open_reason_id"
kv gate_open true

open_nonce="s189-open-${RUN_ID}"
run_app_tcp_probe_with_server open_restore "$open_nonce" tcp_echo_matched \
  tcp_echo_matched "$app_uid"
kv open_restore_traffic tcp_echo_matched

adb_target shell input keyevent HOME >/dev/null 2>&1 || true
start_activity --ez debugRefresh true
capture_s189_status activity_reconnect - "$app_uid" 1 false $((open_revision - 1)) false
activity_reconnect_revision="$(property_value "$RESULT_DIR/activity_reconnect.s189.summary-fragment.properties" active_revision)"
if [[ "$activity_reconnect_revision" != "$open_revision" ]]; then
  fail_closed "Activity reconnect revision $activity_reconnect_revision did not match open revision $open_revision"
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
capture_s189_status restart_after_open - "$app_uid" 1 false $((open_revision - 1)) false
restart_after_open_revision="$(property_value "$RESULT_DIR/restart_after_open.s189.summary-fragment.properties" active_revision)"
if [[ "$restart_after_open_revision" != "$open_revision" ]]; then
  fail_closed "restart revision $restart_after_open_revision did not match open revision $open_revision"
fi
kv restart_after_open_authoritative_revision "$restart_after_open_revision"
kv restart_after_open_same_revision true

restart_nonce="s189-restart-${RUN_ID}"
run_app_tcp_probe_with_server restart_after_open "$restart_nonce" tcp_echo_matched \
  tcp_echo_matched "$app_uid"
kv restart_after_open_traffic tcp_echo_matched

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
echo "SAKAMOTO-189 Root Network Gate: PASS"
