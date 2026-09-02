#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-179 Root fault/recovery/residue real-device acceptance entry point.
#
# PASS means the installed debug APK starts the Root Product VPP on the
# controlled Pixel 6a, S179 Root fault modes settle into the expected counters
# and pass/fail-open/fail-stop outcomes, a supervised cleanup fault blocks STOP
# as mayBeActive, clearing the injected fault removes Root NFQUEUE residue, and
# a fresh Root start runs a new generation that can pass the same LAN probe
# before the final clean stop.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S179_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s179-root-fault-recovery}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="${STATE_PATH:-files/runtime-state/snapshot.properties}"
readonly STATUS_PATH="${STATUS_PATH:-files/product-state/s179-root-fault-recovery.properties}"
readonly CLEANUP_PATH="${CLEANUP_PATH:-files/product-state/s176-root-nfqueue-cleanup.properties}"
readonly PROBE_PATH="${PROBE_PATH:-files/debug/traffic-probe.properties}"
readonly NO_LISTENER_CHAIN="SKM_S179_NL"
readonly NO_LISTENER_QUEUE="179"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s179-root-fault-recovery-product.sh --run --host <controlled-lan-ipv4>

Required:
  --run
  --host / S179_CONTROLLED_LAN_HOST

Optional:
  --serial 28201JEGR0XPAJ
  --base-port / S179_BASE_PORT            default 18179
  --timeout-ms / S179_TIMEOUT_MILLIS      default 5000

Before running, grant Superuser permission for this debug APK in KernelSU
Manager. ADB shell root alone is not APK root authorization evidence.

Required final evidence:
  missing_identity records ingress_identity_missing with no graph lease/verdict
  no_listener_bypass records whether this device/kernel releases packets through --queue-bypass
  graph_submit_fail_open reaches the controlled LAN host and records fail-open
  verdict_failed_definite records only FAILED_DEFINITE and does not retry
  verdict_outcome_unknown records only OUTCOME_UNKNOWN and does not retry
  duplicate/stale completion drops do not issue a second backend verdict
  initial and recovered Root generations are different
  both controlled LAN TCP OUTPUT probes echo their nonce
  cleanup fault publishes state=error/errorCode=cleanup_failed/mayBeActive=true
  clearing the fault reaches productRootNfqueueResidueClean=true
  fresh stop reaches state=stopped/mayBeActive=false/errorCode=
  S179 status contains verdict/fault counters
EOF
}

serial="$S179_SERIAL"
run=0
controlled_host="${S179_CONTROLLED_LAN_HOST:-}"
base_port="${S179_BASE_PORT:-18179}"
timeout_ms="${S179_TIMEOUT_MILLIS:-5000}"

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
    --base-port)
      base_port="${2:-}"
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

if [[ "$serial" != "$S179_SERIAL" ]]; then
  echo "SAKAMOTO-179 only accepts controlled Pixel 6a serial $S179_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S179_CONTROLLED_LAN_HOST" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled host must be an IPv4 literal: $controlled_host" >&2
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]] \
    || (( base_port < 1024 || base_port > 65400 )); then
  echo "invalid base port: $base_port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 100 || timeout_ms > 30000 )); then
  echo "invalid timeout: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/runner.log") 2>&1

kv() {
  printf '%s=%s\n' "$1" "$2"
}

fail_closed() {
  printf 'SAKAMOTO-179-root-fault-recovery=BLOCKED\n' >&2
  printf '%s\n' "$1" >&2
  exit 77
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

remote_shell_quote() {
  local value="$1"
  printf "'"
  printf "%s" "$value" | sed "s/'/'\\\\''/g"
  printf "'"
}

root_shell() {
  local quoted
  quoted="$(remote_shell_quote "$1")"
  adb_target shell "su 0 sh -c $quoted"
}

app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null || true
}

app_uid() {
  adb_target shell run-as "$PACKAGE" id -u | tr -d '\r'
}

cleanup_no_listener_bypass_best_effort() {
  root_shell "iptables -w -t mangle -D OUTPUT -j $NO_LISTENER_CHAIN 2>/dev/null || true; iptables -w -t mangle -F $NO_LISTENER_CHAIN 2>/dev/null || true; iptables -w -t mangle -X $NO_LISTENER_CHAIN 2>/dev/null || true" \
    >/dev/null 2>&1 || true
}

cleanup_product_hooks_best_effort() {
  root_shell "for tool in iptables ip6tables; do for root_chain in OUTPUT INPUT; do \$tool -w -t mangle -D \$root_chain -j SAKAMOTO_PRODUCT_S176_OUTPUT 2>/dev/null || true; \$tool -w -t mangle -D \$root_chain -j SAKAMOTO_PRODUCT_S178_INPUT 2>/dev/null || true; done; for product_chain in SAKAMOTO_PRODUCT_S176_OUTPUT SAKAMOTO_PRODUCT_S178_INPUT; do \$tool -w -t mangle -F \$product_chain 2>/dev/null || true; \$tool -w -t mangle -X \$product_chain 2>/dev/null || true; done; done" \
    >/dev/null 2>&1 || true
}

trap cleanup_no_listener_bypass_best_effort EXIT

field_value() {
  local name="$1"
  local evidence="$2"
  awk -F= -v key="$name" '$1 == key { print $2; exit }' <<<"$evidence"
}

require_exact() {
  local name="$1"
  local expected="$2"
  local evidence="$3"
  if ! grep -Fxq "${name}=${expected}" <<<"$evidence"; then
    printf 'missing or unequal evidence: %s=%s\n' "$name" "$expected" >&2
    return 1
  fi
}

require_ge() {
  local name="$1"
  local minimum="$2"
  local evidence="$3"
  local value
  value="$(field_value "$name" "$evidence")"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( value >= minimum )) || return 1
}

require_equal_fields() {
  local left="$1"
  local right="$2"
  local evidence="$3"
  local left_value right_value
  left_value="$(field_value "$left" "$evidence")"
  right_value="$(field_value "$right" "$evidence")"
  [[ "$left_value" =~ ^[0-9]+$ ]] || return 1
  [[ "$right_value" =~ ^[0-9]+$ ]] || return 1
  [[ "$left_value" == "$right_value" ]]
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

read_snapshot() {
  app_file "$STATE_PATH" | tr -d '\r'
}

read_status_after_refresh() {
  local label="$1"
  start_activity --ez debugRefresh true
  sleep 1
  local status
  status="$(app_file "$STATUS_PATH" | tr -d '\r')"
  printf '%s\n' "$status" >"$RESULT_DIR/product-status.${label}.properties"
  [[ -n "$status" ]]
}

clear_previous_evidence() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$CLEANUP_PATH" "$PROBE_PATH" \
    >/dev/null 2>&1 || true
}

clear_case_evidence() {
  adb_target shell run-as "$PACKAGE" rm -f "$STATUS_PATH" "$PROBE_PATH" \
    >/dev/null 2>&1 || true
}

grant_notification_permission_best_effort() {
  adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
    >/dev/null 2>&1 || true
}

wait_for_root_running() {
  local label="$1"
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    snapshot="$(read_snapshot)"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.poll"
    if grep -Fxq "errorCode=root_authorization_required" <<<"$snapshot"; then
      fail_closed "KernelSU Superuser grant is missing for the installed debug APK"
    fi
    if grep -Fxq "errorCode=notification_permission_required" <<<"$snapshot"; then
      fail_closed "Android notification permission is required before RuntimeService can start"
    fi
    if grep -Fxq "state=running" <<<"$snapshot" \
        && grep -Fxq "profile=root" <<<"$snapshot" \
        && grep -Fxq "coreHealth=ok" <<<"$snapshot" \
        && grep -Fxq "adapterReadiness=root-nfqueue" <<<"$snapshot" \
        && grep -Fxq "protectionRunning=true" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.timeout.properties"
  fail_closed "Product Root runtime did not publish root-nfqueue running state"
}

wait_for_cleanup_fault() {
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 30; attempt++)); do
    snapshot="$(read_snapshot)"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.cleanup-fault.poll"
    if grep -Fxq "state=error" <<<"$snapshot" \
        && grep -Fxq "errorCode=cleanup_failed" <<<"$snapshot" \
        && grep -Fxq "mayBeActive=true" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.cleanup-fault.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.cleanup-fault.timeout.properties"
  fail_closed "cleanup fault did not block the supervised stop as mayBeActive"
}

wait_for_clean_stop() {
  local label="$1"
  local cleanup=""
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 60; attempt++)); do
    cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
    snapshot="$(read_snapshot)"
    printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.${label}.poll"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.poll"
    if grep -Fxq "productRootNfqueueResidueClean=true" <<<"$cleanup" \
        && grep -Fxq "state=stopped" <<<"$snapshot" \
        && grep -Fxq "mayBeActive=false" <<<"$snapshot" \
        && grep -Fxq "errorCode=" <<<"$snapshot"; then
      printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.${label}.properties"
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.${label}.timeout.properties"
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.${label}.timeout.properties"
  fail_closed "Root NFQUEUE/Product Core residue did not cleanly stop"
}

start_host_tcp_echo() {
  local label="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local output="$RESULT_DIR/host-${label}.properties"
  rm -f "$output" "$output.ready" "$RESULT_DIR/host-${label}.server.log"
  python3 - "$host" "$port" "$nonce" "$output" \
    >"$RESULT_DIR/host-${label}.server.log" 2>&1 <<'PY' &
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
nonce = sys.argv[3].encode()
output = sys.argv[4]
ready = output + ".ready"

def write_result(result, request_bytes=0, response_bytes=0, remote=""):
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(f"result={result}\n")
        handle.write(f"host={host}\n")
        handle.write(f"port={port}\n")
        handle.write(f"nonce={nonce.decode()}\n")
        handle.write(f"requestBytes={request_bytes}\n")
        handle.write(f"responseBytes={response_bytes}\n")
        handle.write(f"remote={remote}\n")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(20.0)
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write("ready=true\n")
    try:
        conn, remote = server.accept()
    except socket.timeout:
        write_result("timeout")
    else:
        with conn:
            data = conn.recv(4096)
            matched = data == nonce
            if data:
                conn.sendall(data)
            write_result(
                "matched" if matched else "mismatch",
                len(data),
                len(data) if data else 0,
                f"{remote[0]}:{remote[1]}",
            )
PY
  echo "$!"
}

wait_for_host_ready() {
  local label="$1"
  local file="$RESULT_DIR/host-${label}.properties.ready"
  local attempt
  for ((attempt = 1; attempt <= 50; attempt++)); do
    [[ -f "$file" ]] && return 0
    sleep 0.1
  done
  return 1
}

wait_for_host_echo() {
  local label="$1"
  local file="$RESULT_DIR/host-${label}.properties"
  local attempt
  for ((attempt = 1; attempt <= 25; attempt++)); do
    if [[ -f "$file" ]]; then
      grep -Fxq "result=matched" "$file" && return 0
      cat "$file" >&2
      return 1
    fi
    sleep 1
  done
  return 1
}

wait_for_probe_success() {
  local label="$1"
  local nonce="$2"
  wait_for_probe_result "$label" tcp_echo_matched "$nonce"
}

try_lan_probe_echo() {
  local label="$1"
  local port="$2"
  local nonce="s179-${label}-${RUN_ID}"
  adb_target shell run-as "$PACKAGE" rm -f "$PROBE_PATH" >/dev/null 2>&1 || true
  local server_pid
  server_pid="$(start_host_tcp_echo "$label" "$controlled_host" "$port" "$nonce")"
  if ! wait_for_host_ready "$label"; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    return 1
  fi
  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$controlled_host" \
    --ei debugTrafficPort "$port" \
    --ei debugTrafficTimeoutMillis "$timeout_ms" \
    --es debugTrafficNonce "$nonce"

  local probe=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    probe="$(app_file "$PROBE_PATH" | tr -d '\r')"
    printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.poll"
    if grep -Fxq "nonce=${nonce}" <<<"$probe"; then
      if grep -Fxq "result=tcp_echo_matched" <<<"$probe"; then
        printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.properties"
        if wait_for_host_echo "$label"; then
          wait "$server_pid" >/dev/null 2>&1 || true
          return 0
        fi
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
        return 1
      fi
      if grep -Fq "result=tcp_" <<<"$probe"; then
        printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.failure.properties"
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
        return 1
      fi
    fi
    sleep 1
  done
  printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.timeout.properties"
  kill "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" >/dev/null 2>&1 || true
  return 1
}

wait_for_probe_result() {
  local label="$1"
  local expected="$2"
  local nonce="${3:-}"
  local probe=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    probe="$(app_file "$PROBE_PATH" | tr -d '\r')"
    printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.poll"
    if grep -Fxq "result=${expected}" <<<"$probe" \
        && { [[ -z "$nonce" ]] || grep -Fxq "nonce=${nonce}" <<<"$probe"; }; then
      printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.timeout.properties"
  fail_closed "Controlled LAN TCP probe did not produce ${expected} for ${label}"
}

run_lan_probe() {
  local label="$1"
  local port="$2"
  local attempt
  for ((attempt = 1; attempt <= 4; attempt++)); do
    local attempt_label="${label}-attempt${attempt}"
    local attempt_port=$((port + ((attempt - 1) * 100)))
    if try_lan_probe_echo "$attempt_label" "$attempt_port"; then
      cp "$RESULT_DIR/traffic-probe.${attempt_label}.properties" \
        "$RESULT_DIR/traffic-probe.${label}.properties" 2>/dev/null || true
      cp "$RESULT_DIR/host-${attempt_label}.properties" \
        "$RESULT_DIR/host-${label}.properties" 2>/dev/null || true
      kv "${label//-/_}_probe_attempt" "$attempt"
      return 0
    fi
    start_activity --ez debugRefresh true
    sleep 2
  done
  fail_closed "Controlled LAN TCP probe did not echo nonce for ${label}"
}

run_lan_probe_expect_failure() {
  local label="$1"
  local port="$2"
  local nonce="s179-${label}-${RUN_ID}"
  adb_target shell run-as "$PACKAGE" rm -f "$PROBE_PATH" >/dev/null 2>&1 || true
  local server_pid
  server_pid="$(start_host_tcp_echo "$label" "$controlled_host" "$port" "$nonce")"
  if ! wait_for_host_ready "$label"; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    fail_closed "Controlled LAN host echo server did not become ready for ${label}"
  fi
  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$controlled_host" \
    --ei debugTrafficPort "$port" \
    --ei debugTrafficTimeoutMillis "$timeout_ms" \
    --es debugTrafficNonce "$nonce"
  wait_for_probe_result "$label" tcp_connect_failed "$nonce"
  if [[ -f "$RESULT_DIR/host-${label}.properties" ]] \
      && ! grep -Fxq "result=timeout" "$RESULT_DIR/host-${label}.properties"; then
    cat "$RESULT_DIR/host-${label}.properties" >&2
    fail_closed "Controlled LAN host unexpectedly observed ${label}"
  fi
  kill "$server_pid" >/dev/null 2>&1 || true
  wait "$server_pid" >/dev/null 2>&1 || true
}

install_no_listener_bypass() {
  local uid="$1"
  cleanup_no_listener_bypass_best_effort
  root_shell "iptables -w -t mangle -N $NO_LISTENER_CHAIN; iptables -w -t mangle -A $NO_LISTENER_CHAIN -p tcp -m owner --uid-owner $uid -j NFQUEUE --queue-num $NO_LISTENER_QUEUE --queue-bypass; iptables -w -t mangle -I OUTPUT -j $NO_LISTENER_CHAIN"
}

capture_no_listener_bypass_state() {
  local label="$1"
  root_shell "iptables -w -t mangle -S OUTPUT; iptables -w -t mangle -S $NO_LISTENER_CHAIN 2>/dev/null || true; iptables -w -t mangle -L OUTPUT -n -v --line-numbers; iptables -w -t mangle -L $NO_LISTENER_CHAIN -n -v --line-numbers 2>/dev/null || true" \
    >"$RESULT_DIR/no-listener-bypass.${label}.iptables" 2>&1 || true
}

assert_no_listener_bypass_clean() {
  if root_shell "iptables -w -t mangle -S OUTPUT 2>/dev/null | grep -F $NO_LISTENER_CHAIN >/dev/null; iptables -w -t mangle -S $NO_LISTENER_CHAIN >/dev/null 2>&1" \
      >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

assert_product_hooks_absent() {
  if root_shell "iptables -w -t mangle -S OUTPUT; iptables -w -t mangle -S INPUT; ip6tables -w -t mangle -S OUTPUT; ip6tables -w -t mangle -S INPUT" \
      2>/dev/null | grep -E 'SAKAMOTO_PRODUCT_S176_OUTPUT|SAKAMOTO_PRODUCT_S178_INPUT' >/dev/null; then
    return 1
  fi
  return 0
}

run_no_listener_bypass_case() {
  local uid
  uid="$(app_uid)"
  [[ "$uid" =~ ^[0-9]+$ ]] || fail_closed "cannot resolve app UID for no-listener bypass"
  install_no_listener_bypass "$uid"
  capture_no_listener_bypass_state before-probe
  if try_lan_probe_echo no-listener-bypass "$((base_port + 20))"; then
    kv no_listener_bypass supported
  else
    kv no_listener_bypass unsupported
    kv no_listener_bypass_reason "pixel6a_nfqueue_queue_bypass_did_not_release_without_listener"
  fi
  capture_no_listener_bypass_state after-probe
  cleanup_no_listener_bypass_best_effort
  assert_no_listener_bypass_clean \
    || fail_closed "S179 no-listener bypass chain residue remained"
  assert_product_hooks_absent \
    || fail_closed "S179 no-listener preflight saw Product NFQUEUE hook residue"
  kv no_listener_queue "$NO_LISTENER_QUEUE"
  kv no_listener_uid "$uid"
}

status_has_s179_counters() {
  local status="$1"
  require_ge origin_verdict_attempts 1 "$status" || return 1
  require_ge internal_settlements 1 "$status" || return 1
  require_ge buffer_returns 1 "$status" || return 1
  require_ge verdict_succeeded 1 "$status" || return 1
  require_exact verdict_failed_definite 0 "$status" || return 1
  require_exact verdict_outcome_unknown 0 "$status" || return 1
  require_exact ingress_identity_missing 0 "$status" || return 1
  require_exact graph_submit_fail_opens 0 "$status" || return 1
  require_exact duplicate_completion_drops 0 "$status" || return 1
  require_exact stale_completion_drops 0 "$status" || return 1
}

start_root_with_fault_mode() {
  local label="$1"
  local mode="$2"
  clear_case_evidence
  start_activity --es runtimeRootNfqueueFaultMode "$mode" \
    --ez runtimeStart true --es runtimeProfile root
  wait_for_root_running "${label}-running"
  read_status_after_refresh "${label}-start" \
    || fail_closed "${label} S179 status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.${label}-start.properties")"
  require_exact product.adapter_available 1 "$status" \
    || fail_closed "${label} Root adapter is not available"
  if [[ "$mode" == "none" ]]; then
    require_exact fault_mode "" "$status" \
      || fail_closed "${label} fault mode did not clear"
  else
    require_exact fault_mode "$mode" "$status" \
      || fail_closed "${label} fault mode did not publish"
  fi
}

stop_root_clean() {
  local label="$1"
  start_activity --es runtimeRootNfqueueFaultMode none --ez runtimeStop true
  wait_for_clean_stop "$label"
}

run_missing_identity_case() {
  start_root_with_fault_mode missing-identity missing_identity
  run_lan_probe_expect_failure missing-identity "$((base_port + 2))"
  read_status_after_refresh missing-identity-after-probe \
    || fail_closed "missing_identity status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.missing-identity-after-probe.properties")"
  require_exact fault_mode missing_identity "$status" \
    || fail_closed "missing_identity fault mode missing"
  require_ge ingress_identity_missing 1 "$status" \
    || fail_closed "missing_identity did not record ingress_identity_missing"
  require_exact origin_verdict_attempts 0 "$status" \
    || fail_closed "missing_identity unexpectedly attempted a verdict"
  require_exact internal_settlements 0 "$status" \
    || fail_closed "missing_identity unexpectedly settled a graph lease"
  require_exact buffer_returns 0 "$status" \
    || fail_closed "missing_identity unexpectedly returned a graph buffer"
  require_exact verdict_succeeded 0 "$status" \
    || fail_closed "missing_identity unexpectedly recorded verdict success"
  stop_root_clean missing-identity-stop
  kv missing_identity_result PASS
}

run_graph_submit_fail_open_case() {
  start_root_with_fault_mode graph-submit-fail-open graph_submit_fail_open
  run_lan_probe graph-submit-fail-open "$((base_port + 3))"
  read_status_after_refresh graph-submit-fail-open-after-probe \
    || fail_closed "graph_submit_fail_open status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.graph-submit-fail-open-after-probe.properties")"
  require_exact fault_mode graph_submit_fail_open "$status" \
    || fail_closed "graph_submit_fail_open fault mode missing"
  require_ge graph_submit_fail_opens 1 "$status" \
    || fail_closed "graph_submit_fail_open did not record fail-open"
  require_ge verdict_succeeded 1 "$status" \
    || fail_closed "graph_submit_fail_open did not send an ACCEPT verdict"
  require_exact internal_settlements 0 "$status" \
    || fail_closed "graph_submit_fail_open unexpectedly settled graph work"
  require_exact buffer_returns 0 "$status" \
    || fail_closed "graph_submit_fail_open unexpectedly returned graph work"
  stop_root_clean graph-submit-fail-open-stop
  kv graph_submit_fail_open_result PASS
}

run_verdict_failed_definite_case() {
  start_root_with_fault_mode verdict-failed-definite verdict_failed_definite
  run_lan_probe_expect_failure verdict-failed-definite "$((base_port + 4))"
  read_status_after_refresh verdict-failed-definite-after-probe \
    || fail_closed "verdict_failed_definite status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.verdict-failed-definite-after-probe.properties")"
  require_exact fault_mode verdict_failed_definite "$status" \
    || fail_closed "verdict_failed_definite fault mode missing"
  require_ge verdict_failed_definite 1 "$status" \
    || fail_closed "verdict_failed_definite did not record FAILED_DEFINITE"
  require_exact verdict_outcome_unknown 0 "$status" \
    || fail_closed "verdict_failed_definite leaked OUTCOME_UNKNOWN"
  require_equal_fields origin_verdict_attempts internal_settlements "$status" \
    || fail_closed "verdict_failed_definite retried outside one graph settlement"
  require_equal_fields origin_verdict_attempts buffer_returns "$status" \
    || fail_closed "verdict_failed_definite lost graph buffer accounting"
  stop_root_clean verdict-failed-definite-stop
  kv verdict_failed_definite_result PASS
}

run_verdict_outcome_unknown_case() {
  start_root_with_fault_mode verdict-outcome-unknown verdict_outcome_unknown
  run_lan_probe_expect_failure verdict-outcome-unknown "$((base_port + 5))"
  read_status_after_refresh verdict-outcome-unknown-after-probe \
    || fail_closed "verdict_outcome_unknown status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.verdict-outcome-unknown-after-probe.properties")"
  require_exact fault_mode verdict_outcome_unknown "$status" \
    || fail_closed "verdict_outcome_unknown fault mode missing"
  require_ge verdict_outcome_unknown 1 "$status" \
    || fail_closed "verdict_outcome_unknown did not record OUTCOME_UNKNOWN"
  require_exact verdict_failed_definite 0 "$status" \
    || fail_closed "verdict_outcome_unknown leaked FAILED_DEFINITE"
  require_equal_fields origin_verdict_attempts internal_settlements "$status" \
    || fail_closed "verdict_outcome_unknown retried outside one graph settlement"
  require_equal_fields origin_verdict_attempts buffer_returns "$status" \
    || fail_closed "verdict_outcome_unknown lost graph buffer accounting"
  stop_root_clean verdict-outcome-unknown-stop
  kv verdict_outcome_unknown_result PASS
}

run_duplicate_completion_case() {
  start_root_with_fault_mode duplicate-completion duplicate_completion
  run_lan_probe duplicate-completion "$((base_port + 6))"
  read_status_after_refresh duplicate-completion-after-probe \
    || fail_closed "duplicate_completion status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.duplicate-completion-after-probe.properties")"
  require_exact fault_mode duplicate_completion "$status" \
    || fail_closed "duplicate_completion fault mode missing"
  require_ge duplicate_completion_drops 1 "$status" \
    || fail_closed "duplicate_completion did not record duplicate drop"
  require_equal_fields origin_verdict_attempts verdict_succeeded "$status" \
    || fail_closed "duplicate_completion attempted a second verdict"
  require_exact stale_completion_drops 0 "$status" \
    || fail_closed "duplicate_completion leaked stale drops"
  stop_root_clean duplicate-completion-stop
  kv duplicate_completion_result PASS
}

run_stale_completion_case() {
  start_root_with_fault_mode stale-completion stale_completion
  run_lan_probe stale-completion "$((base_port + 7))"
  read_status_after_refresh stale-completion-after-probe \
    || fail_closed "stale_completion status was not published"
  local status
  status="$(cat "$RESULT_DIR/product-status.stale-completion-after-probe.properties")"
  require_exact fault_mode stale_completion "$status" \
    || fail_closed "stale_completion fault mode missing"
  require_ge stale_completion_drops 1 "$status" \
    || fail_closed "stale_completion did not record stale drop"
  require_equal_fields origin_verdict_attempts verdict_succeeded "$status" \
    || fail_closed "stale_completion attempted a second verdict"
  require_exact duplicate_completion_drops 0 "$status" \
    || fail_closed "stale_completion leaked duplicate drops"
  stop_root_clean stale-completion-stop
  kv stale_completion_result PASS
}

device_state="$(adb_target get-state 2>/dev/null || true)"
[[ "$device_state" == "device" ]] || fail_closed "ADB device $serial is not connected"
model="$(adb_target shell getprop ro.product.model | tr -d '\r')"
kv device_serial "$serial"
kv device_model "$model"
kv package "$PACKAGE"
kv host "$controlled_host"
kv base_port "$base_port"

clear_previous_evidence
grant_notification_permission_best_effort
start_activity --ez runtimeCleanupFault false --es runtimeRootNfqueueFaultMode none \
  --ez runtimeStop true
sleep 1
cleanup_product_hooks_best_effort
assert_product_hooks_absent \
  || fail_closed "S179 preflight saw Product NFQUEUE hook residue"

run_no_listener_bypass_case
run_missing_identity_case
run_graph_submit_fail_open_case
run_verdict_failed_definite_case
run_verdict_outcome_unknown_case
run_duplicate_completion_case
run_stale_completion_case

start_root_with_fault_mode initial none
read_status_after_refresh initial || fail_closed "initial S179 status was not published"
initial_status="$(cat "$RESULT_DIR/product-status.initial.properties")"
require_exact product.adapter_available 1 "$initial_status" \
  || fail_closed "initial Root adapter is not available"
initial_generation="$(field_value root_nfqueue_generation "$initial_status")"
[[ "$initial_generation" =~ ^[0-9]+$ ]] && (( initial_generation > 0 )) \
  || fail_closed "initial Root generation is missing"
run_lan_probe initial "$base_port"
read_status_after_refresh initial-after-probe \
  || fail_closed "initial post-probe S179 status was not published"
status_has_s179_counters "$(cat "$RESULT_DIR/product-status.initial-after-probe.properties")" \
  || fail_closed "initial status lost S179 verdict/fault evidence"

start_activity --ez runtimeCleanupFault true --ez runtimeStop true
wait_for_cleanup_fault
start_activity --ez runtimeCleanupFault false --ez runtimeStop true
wait_for_clean_stop "after-fault-clear"

start_root_with_fault_mode recovered none
read_status_after_refresh recovered || fail_closed "recovered S179 status was not published"
recovered_status="$(cat "$RESULT_DIR/product-status.recovered.properties")"
require_exact product.adapter_available 1 "$recovered_status" \
  || fail_closed "recovered Root adapter is not available"
recovered_generation="$(field_value root_nfqueue_generation "$recovered_status")"
[[ "$recovered_generation" =~ ^[0-9]+$ ]] && (( recovered_generation > initial_generation )) \
  || fail_closed "fresh recovery generation did not advance"
run_lan_probe recovered "$((base_port + 1))"
read_status_after_refresh recovered-after-probe \
  || fail_closed "recovered post-probe S179 status was not published"
status_has_s179_counters "$(cat "$RESULT_DIR/product-status.recovered-after-probe.properties")" \
  || fail_closed "recovered status lost S179 verdict/fault evidence"

start_activity --es runtimeRootNfqueueFaultMode none --ez runtimeStop true
wait_for_clean_stop "final"

cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
snapshot="$(read_snapshot)"
printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.final.properties"
printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.final.properties"
require_exact productRootNfqueueResidueClean true "$cleanup" \
  || fail_closed "final Root NFQUEUE residue was not clean"
require_exact state stopped "$snapshot" \
  || fail_closed "final runtime state is not stopped"
require_exact mayBeActive false "$snapshot" \
  || fail_closed "final runtime mayBeActive is not false"
require_exact errorCode "" "$snapshot" \
  || fail_closed "final runtime retained an error"

kv initial_generation "$initial_generation"
kv recovered_generation "$recovered_generation"
kv cleanup_fault_blocks_stop true
kv recovery_lan_probe matched
kv final_residue_clean true
printf 'SAKAMOTO-179-root-fault-recovery=PASS\n'
