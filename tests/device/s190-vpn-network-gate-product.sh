#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-190 VPN Network Gate real-device acceptance.
#
# PASS means the installed debug APK seeds one VPN-context Network Gate through
# the same LocalProductBackend/Rust Product Store path, switches to the VPN
# Product profile, proves the VPN adapter attaches the same policy facts to TUN
# packets, blocks VPN-bound TCP before Flow Stack admission, opens the successor
# rule, proves traffic restores, and stops cleanly.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S190_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s190-vpn-network-gate}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s190-device-run.lock"
readonly S190_WAIT_ATTEMPTS="${S190_WAIT_ATTEMPTS:-180}"
readonly S190_ADB_COMMAND_TIMEOUT_SECONDS="${S190_ADB_COMMAND_TIMEOUT_SECONDS:-20}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly S188_STATUS_PATH="files/product-state/s188-empty-policy-snapshot.properties"
readonly ROOT_SEED_PATH="files/product-state/s189-root-network-gate.properties"
readonly S190_STATUS_PATH="files/product-state/s190-vpn-network-gate.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly EMPTY_STORE_PATH="files/product-policy/empty-intent.properties"
readonly GATE_STORE_PATH="files/product-policy/policy-bundle.properties"
readonly TRAFFIC_PROBE_PATH="files/debug/traffic-probe.properties"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s190-vpn-network-gate-product.sh --run --host <controlled-lan-ipv4>

Required:
  --run
  --host / S190_CONTROLLED_LAN_HOST

Optional:
  --serial 28201JEGR0XPAJ
  --port / S190_TCP4_PORT             default 19090
  --timeout-ms / S190_TIMEOUT_MILLIS  default 5000

Before running, install the debug APK and approve Android VpnService if the
Pixel 6a prompts for it.

Required final evidence:
  root_seed_same_revision=true
  vpn_baseline_traffic=tcp_echo_matched
  gate_blocked=true
  blocked_traffic=tcp_connect_failed
  policy_drop_recorded=true
  vpn_adapter_policy_drop_completion=true
  vpn_flow_stack_admissions_unchanged_on_drop=true
  gate_open=true
  open_restore_traffic=tcp_echo_matched
  root_vpn_shared_product_store=true
  final_residue_clean=true
EOF
}

serial="$S190_SERIAL"
run=0
controlled_host="${S190_CONTROLLED_LAN_HOST:-}"
port="${S190_TCP4_PORT:-19090}"
timeout_ms="${S190_TIMEOUT_MILLIS:-5000}"
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

if [[ "$serial" != "$S190_SERIAL" ]]; then
  echo "SAKAMOTO-190 only accepts controlled Pixel 6a serial $S190_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S190_CONTROLLED_LAN_HOST" >&2
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
  echo "SAKAMOTO-190 FAIL: $1" >&2
  exit 1
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if timeout "$S190_ADB_COMMAND_TIMEOUT_SECONDS" "$ADB" "$@"; then
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
    "$ROOT_SEED_PATH" \
    "$S190_STATUS_PATH" \
    "$PRODUCT_STATE_PATH" \
    "$PRODUCT_TRANSACTIONS_PATH" \
    "$EMPTY_STORE_PATH" \
    "$GATE_STORE_PATH" \
    "$TRAFFIC_PROBE_PATH" >/dev/null 2>&1 || true
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

number_property() {
  local file="$1"
  local key="$2"
  local value
  value="$(property_value "$file" "$key")"
  if ! [[ "$value" =~ ^-?[0-9]+$ ]]; then
    fail_closed "$key is not numeric in $file"
  fi
  printf '%s\n' "$value"
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
    if [[ "$lock_args" == *"s190-vpn-network-gate-product.sh"* ]]; then
      fail_closed "another S190 runner is active: pid=$lock_pid"
    fi
    kv stale_run_lock_pid_reused "$lock_pid"
  fi
  rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
  rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "$RUN_LOCK_DIR/pid"
    kv device_run_lock_acquired true
    return
  fi
  fail_closed "could not acquire S190 device run lock"
}

wait_for_state() {
  local expected="$1"
  local output="$RESULT_DIR/state-${expected}.properties"
  local attempt
  for attempt in $(seq 1 "$S190_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fq "state=${expected}" "$output"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_profile_ready() {
  local profile="$1"
  local adapter="$2"
  local output="$RESULT_DIR/state-${profile}-running.properties"
  local attempt
  for attempt in $(seq 1 "$S190_WAIT_ATTEMPTS"); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fq "state=running" "$output" \
        && grep -Fq "profile=${profile}" "$output" \
        && grep -Fq "adapterReadiness=${adapter}" "$output" \
        && grep -Fq "coreHealth=ok" "$output" \
        && grep -Fq "mayBeActive=true" "$output"; then
      kv "${profile}.runtime.generation" "$(property_value "$output" generation)"
      kv "${profile}.runtime.adapterReadiness" "$adapter"
      return 0
    fi
    if grep -Fq 'errorCode=vpn_authorization_required' "$output"; then
      fail_closed "VPN start requires Android VpnService approval for $PACKAGE"
    fi
    if grep -Fq 'errorCode=root_authorization_required' "$output"; then
      fail_closed "Root start requires KernelSU Superuser grant for $PACKAGE"
    fi
    if grep -Fq 'errorCode=notification_permission_required' "$output"; then
      fail_closed "start requires Android notification permission"
    fi
    sleep 0.5
  done
  fail_closed "$profile Product Core did not reach running/$adapter"
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

wait_for_probe_result() {
  local label="$1"
  local expected="$2"
  local expected_uid="$3"
  local expected_nonce="$4"
  local output="$RESULT_DIR/${label}.traffic-probe.properties"
  local attempt
  for attempt in $(seq 1 "$S190_WAIT_ATTEMPTS"); do
    read_app_file "$TRAFFIC_PROBE_PATH" > "$output"
    if grep -Fq "nonce=${expected_nonce}" "$output" \
        && grep -Fq "result=${expected}" "$output"; then
      local uid
      uid="$(property_value "$output" uid)"
      if [[ "$uid" != "$expected_uid" ]]; then
        fail_closed "${label} probe UID $uid did not match installed app UID $expected_uid"
      fi
      if ! grep -Fq "bindResult=bound" "$output"; then
        fail_closed "${label} probe did not bind to Android VPN Network"
      fi
      if ! grep -Fq "bindToVpn=true" "$output"; then
        fail_closed "${label} probe was not marked VPN-bound"
      fi
      kv "${label}.traffic" "$expected"
      kv "${label}.traffic_probe_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} traffic probe did not report ${expected}; see ${output}"
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
    --ei debugTrafficTimeoutMillis "$timeout_ms" \
    --ez debugTrafficBindToVpn true
  wait_for_probe_result "$label" "$expected_probe" "$uid" "$nonce"
  wait "$server_pid" || true
  server_pid=""
  if ! grep -Fq "result=${expected_server}" "$server_log"; then
    fail_closed "${label} server expected ${expected_server}; see ${server_log}"
  fi
  kv "${label}.server" "$expected_server"
}

validate_s190_status_file() {
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

need("schema", "s190-vpn-network-gate/v1")
if expected_stage != "-":
    need("stage", expected_stage)
need("profile", "vpn")
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
truthy("root_vpn_shared_product_store")
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
need("rust_product_store", "product-policy/policy-bundle.properties")
truthy("rust_product_store_single_writer")
truthy("vpn_tun_status_available")
if number("vpn_policy_hint_subject_uid") != expected_uid:
    raise SystemExit("vpn policy subject hint mismatch")
if number("vpn_policy_hint_network_context") != expected_context:
    raise SystemExit("vpn policy network hint mismatch")
if number("vpn_tun_fd_attached") <= 0:
    raise SystemExit("VPN TUN fd was not attached")
falsey("physical_nfqueue_completion")
if require_drop:
    truthy("policy_drop_recorded")
    truthy("vpn_adapter_policy_drop_completion")
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
    need("policy_last_drop_packet_origin", "TUN")
    need("expected_policy_last_drop_packet_origin", "1")
print(f"active_revision={active}")
print(f"gate_rule_id={rule_id}")
print(f"gate_reason_id={reason_id}")
print(f"gate_blocked={str(expected_blocked).lower()}")
print(f"vpn_flow_stack_admissions={number('vpn_flow_stack_admissions')}")
print(f"vpn_direct_tcp4_connect_attempts={number('vpn_direct_tcp4_connect_attempts')}")
print(f"vpn_direct_tcp4_connect_succeeded={number('vpn_direct_tcp4_connect_succeeded')}")
if require_drop:
    print(f"policy_drop_records={number('policy_drop_records')}")
    print("policy_drop_recorded=true")
    print("vpn_adapter_policy_drop_completion=true")
PY
}

capture_s190_status() {
  local label="$1"
  local expected_stage="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_blocked="$5"
  local min_revision="${6:-0}"
  local require_drop="${7:-false}"
  local output="$RESULT_DIR/${label}.s190.properties"
  local values="$RESULT_DIR/${label}.s190.summary-fragment.properties"
  local attempt
  for attempt in $(seq 1 "$S190_WAIT_ATTEMPTS"); do
    read_app_file "$S190_STATUS_PATH" > "$output"
    if validate_s190_status_file "$output" "$expected_stage" "$expected_uid" \
        "$expected_context" "$expected_blocked" "$min_revision" "$require_drop" \
        > "$values" 2>"$RESULT_DIR/${label}.s190.validation.stderr"; then
      while IFS= read -r line; do
        kv "${label}.${line%%=*}" "${line#*=}"
      done < "$values"
      kv "${label}.status_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} S190 status did not become valid; see ${output}"
}

capture_root_seed_status() {
  local expected_uid="$1"
  local output="${2:-$RESULT_DIR/root_seed.s189.properties}"
  local label="${3:-root_seed}"
  local min_revision="${4:-0}"
  local attempt
  for attempt in $(seq 1 "$S190_WAIT_ATTEMPTS"); do
    read_app_file "$ROOT_SEED_PATH" > "$output"
    if grep -Fq "schema=s189-root-network-gate/v1" "$output" \
        && grep -Fq "profile=root" "$output" \
        && grep -Fq "state=running" "$output" \
        && grep -Fq "gate_subject_uid=${expected_uid}" "$output" \
        && grep -Fq "gate_network_context=3" "$output" \
        && grep -Fq "gate_blocked=false" "$output" \
        && truthy_property "$output" "gate_snapshot" \
        && truthy_property "$output" "revision_match" \
        && truthy_property "$output" "worker_revision_match"; then
      local active_revision
      active_revision="$(property_value "$output" active_revision)"
      if ! [[ "$active_revision" =~ ^[0-9]+$ ]] || (( active_revision <= min_revision )); then
        sleep 0.5
        continue
      fi
      kv "${label}.active_revision" "$active_revision"
      kv "${label}.gate_rule_id" "$(property_value "$output" gate_rule_id)"
      kv "${label}.gate_reason_id" "$(property_value "$output" gate_reason_id)"
      kv "${label}.status_file" "$output"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} VPN-context Network Gate status did not become valid"
}

validate_gate_store_matches() {
  local label="$1"
  local expected_revision="$2"
  local expected_uid="$3"
  local expected_context="$4"
  local expected_blocked="$5"
  local output="$RESULT_DIR/${label}.policy-bundle.properties"
  read_app_file "$GATE_STORE_PATH" > "$output"
  python3 - "$output" "$expected_revision" "$expected_uid" "$expected_context" \
    "$expected_blocked" <<'PY'
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
if int(props.get("snapshotHash", "0")) <= 0:
    raise SystemExit("snapshotHash missing")
PY
  kv "${label}.rust_product_store_readback" true
}

compare_policy_fields() {
  local label="$1"
  local left="$2"
  local right="$3"
  local key
  for key in active_revision gate_subject_uid gate_network_context gate_rule_id \
    gate_reason_id gate_blocked; do
    if [[ "$(property_value "$left" "$key")" != "$(property_value "$right" "$key")" ]]; then
      fail_closed "${label} policy field mismatch: ${key}"
    fi
  done
  kv "${label}.parity" true
  kv "${label}.same_revision" true
  kv "${label}.same_policy_fields" true
}

require_counter_unchanged() {
  local label="$1"
  local key="$2"
  local before="$3"
  local after="$4"
  if [[ "$(number_property "$before" "$key")" != "$(number_property "$after" "$key")" ]]; then
    fail_closed "${label} changed ${key}"
  fi
  kv "${label}_${key}_unchanged" true
}

stop_runtime() {
  clear_app_file "$STATE_PATH"
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  wait_for_state stopped >/dev/null 2>&1 || true
}

kv acceptance SAKAMOTO-190-vpn-network-gate
kv serial "$serial"
kv package "$PACKAGE"
kv host "$controlled_host"
kv port "$port"
kv result_dir "$RESULT_DIR"

acquire_run_lock

adb_raw devices > "$RESULT_DIR/adb-devices.txt" 2>"$RESULT_DIR/adb-devices.stderr"
if ! tr -d '\r' < "$RESULT_DIR/adb-devices.txt" \
    | awk 'NR > 1 && $1 == serial && $2 == "device" { found = 1 } END { exit found ? 0 : 1 }' serial="$serial"; then
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
kv network_context vpn
kv network_context_id 3

stop_runtime
clear_product_policy_files

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_profile_ready root root-nfqueue

start_activity --es debugSetNetworkGateSubject "$subject" \
  --es debugSetNetworkGateContext vpn \
  --ez debugSetNetworkGateBlocked false
capture_root_seed_status "$app_uid"
ROOT_SEED_STATUS="$RESULT_DIR/root_seed.s189.properties"
root_seed_revision="$(property_value "$ROOT_SEED_STATUS" active_revision)"
validate_gate_store_matches root_seed "$root_seed_revision" "$app_uid" 3 false

stop_runtime
if ! wait_for_state stopped >/dev/null 2>&1; then
  fail_closed "Root Product Core did not stop cleanly before VPN start"
fi
kv root_seed_stopped_clean true

start_activity --ez runtimeStart true --es runtimeProfile vpn
wait_for_profile_ready vpn vpn-tun-hev-lwip
capture_s190_status vpn_start - "$app_uid" 3 false $((root_seed_revision - 1)) false
VPN_START_STATUS="$RESULT_DIR/vpn_start.s190.properties"
compare_policy_fields root_seed.vpn_start "$ROOT_SEED_STATUS" "$VPN_START_STATUS"
kv root_vpn_shared_product_store true

baseline_nonce="s190-vpn-baseline-${RUN_ID}"
run_app_tcp_probe_with_server vpn_baseline "$baseline_nonce" tcp_echo_matched \
  tcp_echo_matched "$app_uid"
kv vpn_baseline_traffic tcp_echo_matched

clear_app_file "$S190_STATUS_PATH"
start_activity --es debugSetNetworkGateSubject "$subject" \
  --es debugSetNetworkGateContext vpn \
  --ez debugSetNetworkGateBlocked true
capture_s190_status gate_blocked gate_blocked "$app_uid" 3 true \
  "$root_seed_revision" false
block_revision="$(property_value "$RESULT_DIR/gate_blocked.s190.summary-fragment.properties" active_revision)"
validate_gate_store_matches gate_blocked "$block_revision" "$app_uid" 3 true
kv gate_blocked true

blocked_nonce="s190-vpn-blocked-${RUN_ID}"
run_app_tcp_probe_with_server blocked "$blocked_nonce" tcp_connect_failed \
  tcp_echo_unseen "$app_uid"
kv blocked_traffic tcp_connect_failed

start_activity --ez debugRefresh true
capture_s190_status gate_drop - "$app_uid" 3 true $((block_revision - 1)) true
require_counter_unchanged vpn_flow_stack_admissions \
  vpn_flow_stack_admissions \
  "$RESULT_DIR/gate_blocked.s190.properties" \
  "$RESULT_DIR/gate_drop.s190.properties"
require_counter_unchanged vpn_direct_tcp4_connect_attempts \
  vpn_direct_tcp4_connect_attempts \
  "$RESULT_DIR/gate_blocked.s190.properties" \
  "$RESULT_DIR/gate_drop.s190.properties"
kv vpn_flow_stack_admissions_unchanged_on_drop true
kv vpn_transport_attempts_unchanged_on_drop true

clear_app_file "$S190_STATUS_PATH"
start_activity --es debugSetNetworkGateSubject "$subject" \
  --es debugSetNetworkGateContext vpn \
  --ez debugSetNetworkGateBlocked false
capture_s190_status gate_open gate_open "$app_uid" 3 false "$block_revision" false
open_revision="$(property_value "$RESULT_DIR/gate_open.s190.summary-fragment.properties" active_revision)"
VPN_OPEN_STATUS="$RESULT_DIR/gate_open.s190.properties"
validate_gate_store_matches gate_open "$open_revision" "$app_uid" 3 false
kv gate_open true

open_nonce="s190-vpn-open-${RUN_ID}"
run_app_tcp_probe_with_server open_restore "$open_nonce" tcp_echo_matched \
  tcp_echo_matched "$app_uid"
kv open_restore_traffic tcp_echo_matched

stop_runtime
if ! wait_for_state stopped >/dev/null 2>&1; then
  fail_closed "VPN Product Core did not stop cleanly before final Root readback"
fi
clear_app_file "$ROOT_SEED_PATH"
start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_profile_ready root root-nfqueue
ROOT_FINAL_STATUS="$RESULT_DIR/root_final.s189.properties"
capture_root_seed_status "$app_uid" "$ROOT_FINAL_STATUS" root_final $((open_revision - 1))
compare_policy_fields final_root_vpn "$ROOT_FINAL_STATUS" "$VPN_OPEN_STATUS"
kv final_root_vpn_same_revision true

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
echo "SAKAMOTO-190 VPN Network Gate: PASS"
