#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-187 Worker/core placement and engineering guardrails.
#
# PASS means the installed debug APK starts Product Core with one fixed Android
# VPP placement before traffic, keeps that placement stable while Root and VPN
# each pass representative IPv4/IPv6 TCP/UDP app traffic, records bounded
# process/fd/thread/RSS/CPU/latency evidence, performs a short VPN->Root switch,
# and stops with zero product residue. These thresholds are recovery
# engineering guardrails, not release SLOs.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S187_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s187-worker-core-guardrails}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s187-device-run.lock"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s187-worker-core-guardrails.properties"
readonly ROOT_STATUS_PATH="files/product-state/s178-root-nfqueue-matrix.properties"
readonly VPN_STATUS_PATH="files/product-state/s184-vpn-network-epoch.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"
readonly ROOT_PROFILE_PATH="files/profiles/root/vpp"
readonly VPN_PROFILE_PATH="files/profiles/vpn/vpp"
readonly ROOT_OUTPUT_CHAIN="SAKAMOTO_PRODUCT_S176_OUTPUT"
readonly ROOT_INPUT_CHAIN="SAKAMOTO_PRODUCT_S178_INPUT"
readonly OWNER_TOKEN_ENV_KEY="SAKAMOTO_VPP_OWNER_TOKEN"

readonly S187_IDLE_SEC="${S187_IDLE_SEC:-5}"
readonly S187_MAX_IDLE_CPU_PCT="${S187_MAX_IDLE_CPU_PCT:-20.00}"
readonly S187_MAX_ACTIVE_CPU_PCT="${S187_MAX_ACTIVE_CPU_PCT:-150.00}"
readonly S187_MAX_PROBE_LATENCY_MS="${S187_MAX_PROBE_LATENCY_MS:-8000}"
readonly S187_MAX_THREAD_COUNT="${S187_MAX_THREAD_COUNT:-48}"
readonly S187_MAX_FD_COUNT="${S187_MAX_FD_COUNT:-256}"
readonly S187_MAX_RSS_KB="${S187_MAX_RSS_KB:-262144}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s187-worker-core-guardrails-product.sh --run \
    --host4 <controlled-lan-ipv4> --host6 <controlled-lan-ipv6>

Required:
  --run
  --host4 / S187_CONTROLLED_LAN_HOST4
  --host6 / S187_CONTROLLED_LAN_HOST6

Optional:
  --serial 28201JEGR0XPAJ
  --base-port / S187_BASE_PORT       default 18700
  --timeout-ms / S187_TIMEOUT_MILLIS default 5000

Before running, grant this debug APK root permission in KernelSU Manager and
approve it as an Android VPN service. Device PASS is the only PASS.
EOF
}

serial="$S187_SERIAL"
run=0
host4="${S187_CONTROLLED_LAN_HOST4:-}"
host6="${S187_CONTROLLED_LAN_HOST6:-}"
base_port="${S187_BASE_PORT:-18700}"
timeout_ms="${S187_TIMEOUT_MILLIS:-5000}"

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
    --host4)
      host4="${2:-}"
      shift 2
      ;;
    --host6)
      host6="${2:-}"
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

if [[ "$serial" != "$S187_SERIAL" ]]; then
  echo "SAKAMOTO-187 only accepts controlled Pixel 6a serial $S187_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$host4" || -z "$host6" ]]; then
  echo "missing --host4/--host6 or S187_CONTROLLED_LAN_HOST4/HOST6" >&2
  usage >&2
  exit 2
fi
if ! [[ "$host4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled IPv4 host must be an IPv4 literal: $host4" >&2
  exit 2
fi
python3 - "$host6" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if address.version != 6:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if getattr(address, "ipv4_mapped", None) is not None:
    raise SystemExit("controlled IPv6 host must not be IPv4-mapped")
if address.is_loopback or address.is_unspecified or address.is_global:
    raise SystemExit("controlled IPv6 host must be reachable LAN, not loopback/public")
PY
if ! [[ "$base_port" =~ ^[0-9]+$ ]] || (( base_port < 1024 || base_port > 65520 )); then
  echo "invalid base port: $base_port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
thresholds="$RESULT_DIR/thresholds.properties"
: > "$summary"
server_pid=""
root_shell_call=0
run_lock_acquired=0

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

write_thresholds() {
  {
    printf 'pre_registered_thresholds=true\n'
    printf 'threshold_scope=engineering_guardrail_not_release_slo\n'
    printf 'max_idle_cpu_pct=%s\n' "$S187_MAX_IDLE_CPU_PCT"
    printf 'max_active_cpu_pct=%s\n' "$S187_MAX_ACTIVE_CPU_PCT"
    printf 'max_probe_latency_ms=%s\n' "$S187_MAX_PROBE_LATENCY_MS"
    printf 'max_thread_count=%s\n' "$S187_MAX_THREAD_COUNT"
    printf 'max_fd_count=%s\n' "$S187_MAX_FD_COUNT"
    printf 'max_rss_kb=%s\n' "$S187_MAX_RSS_KB"
    printf 'idle_window_sec=%s\n' "$S187_IDLE_SEC"
  } > "$thresholds"
  while IFS= read -r line; do
    kv "threshold.${line%%=*}" "${line#*=}"
  done < "$thresholds"
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
  local quoted output status attempt stderr_path call_id
  quoted="$(remote_shell_quote "$1")"
  root_shell_call=$((root_shell_call + 1))
  call_id="$root_shell_call"
  for attempt in 1 2 3; do
    stderr_path="$RESULT_DIR/root-shell.${call_id}.${attempt}.stderr"
    set +e
    output="$(adb_target shell "su 0 sh -c $quoted" 2>"$stderr_path" | tr -d '\r')"
    status=$?
    set -e
    if (( status == 0 )); then
      printf '%s\n' "$output"
      return 0
    fi
    sleep 1
  done
  if [[ -n "$output" ]]; then
    printf '%s\n' "$output"
  fi
  return "$status"
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "$RESULT_DIR/am-start.log" 2>&1
}

finish_server() {
  if [[ -n "$server_pid" ]]; then
    wait "$server_pid" || true
    server_pid=""
  fi
}

cleanup() {
  local status=$?
  set +e
  finish_server
  if [[ "$run_lock_acquired" == 1 ]]; then
    start_activity --ez runtimeCleanupFault false --ez runtimeStop true >/dev/null 2>&1 || true
    rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-187 FAIL: $1" >&2
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
  if [[ -r "$RUN_LOCK_DIR/pid" ]]; then
    IFS= read -r lock_pid < "$RUN_LOCK_DIR/pid" || true
  fi
  if [[ "$lock_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$lock_pid" 2>/dev/null; then
    rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
    if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
      run_lock_acquired=1
      printf '%s\n' "$$" > "$RUN_LOCK_DIR/pid"
      kv device_run_lock_acquired true
      kv device_run_lock_recovered_stale_pid "$lock_pid"
      return
    fi
  fi

  fail_closed "another S187 device runner is active"
}

now_ms() {
  python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

property_value() {
  local key="$1"
  local file="$2"
  awk -F= -v wanted="$key" '
    $1 == wanted {
      value = substr($0, index($0, "=") + 1)
      sub(/\r$/, "", value)
      print value
      exit
    }' "$file"
}

require_property() {
  local key="$1"
  local expected="$2"
  local file="$3"
  grep -Fxq "${key}=${expected}" "$file" \
    || fail_closed "$key=$expected missing in $file"
}

require_numeric_positive() {
  local key="$1"
  local file="$2"
  local value
  value="$(property_value "$key" "$file")"
  [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )) \
    || fail_closed "$key is not positive in $file"
}

require_numeric_le() {
  local label="$1"
  local value="$2"
  local max="$3"
  python3 - "$label" "$value" "$max" <<'PY' || fail_closed "$label=$value exceeds $max"
import sys
label, value, maximum = sys.argv[1:]
try:
    ok = float(value) <= float(maximum)
except ValueError:
    ok = False
raise SystemExit(0 if ok else 1)
PY
}

clear_app_files() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$ROOT_STATUS_PATH" "$VPN_STATUS_PATH" \
    "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" >/dev/null 2>&1 || true
}

snapshot_to_file() {
  local label="$1"
  read_app_file "$STATE_PATH" > "$RESULT_DIR/snapshot.${label}.properties"
}

s187_status_to_file() {
  local label="$1"
  read_app_file "$STATUS_PATH" > "$RESULT_DIR/s187-status.${label}.properties"
}

start_profile() {
  local profile="$1"
  start_activity --ez runtimeCleanupFault false \
    --es runtimeRootNfqueueFaultMode none --es runtimeVpnFaultMode none \
    --ez runtimeStart true --es runtimeProfile "$profile"
}

stop_runtime() {
  start_activity --ez runtimeCleanupFault false --ez runtimeStop true
}

refresh_product_status() {
  start_activity --ez debugRefresh true
}

wait_for_running() {
  local label="$1"
  local profile="$2"
  local adapter="$3"
  local deadline=$((SECONDS + 70))
  local next_start_retry=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    snapshot_to_file "$label"
    if grep -Fxq "errorCode=root_authorization_required" \
        "$RESULT_DIR/snapshot.${label}.properties"; then
      fail_closed "KernelSU Superuser grant is missing for the installed debug APK"
    fi
    if grep -Fxq "errorCode=vpn_authorization_required" \
        "$RESULT_DIR/snapshot.${label}.properties"; then
      fail_closed "VPN authorization is missing; approve the Android VPN dialog and rerun"
    fi
    if grep -Fxq "errorCode=notification_permission_required" \
        "$RESULT_DIR/snapshot.${label}.properties"; then
      fail_closed "Android notification permission is required before RuntimeService can start"
    fi
    if grep -Fxq "state=running" "$RESULT_DIR/snapshot.${label}.properties" \
        && grep -Fxq "profile=${profile}" "$RESULT_DIR/snapshot.${label}.properties" \
        && grep -Fxq "adapterReadiness=${adapter}" \
          "$RESULT_DIR/snapshot.${label}.properties"; then
      s187_status_to_file "$label"
      require_property schema s187-worker-core-guardrails/v1 \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property profile "$profile" "$RESULT_DIR/s187-status.${label}.properties"
      require_property state running "$RESULT_DIR/s187-status.${label}.properties"
      require_property main_core 0 "$RESULT_DIR/s187-status.${label}.properties"
      require_property worker_count 2 "$RESULT_DIR/s187-status.${label}.properties"
      require_property worker_cores 1-2 "$RESULT_DIR/s187-status.${label}.properties"
      require_property vpp_main_core 0 "$RESULT_DIR/s187-status.${label}.properties"
      require_property vpp_worker_count 2 "$RESULT_DIR/s187-status.${label}.properties"
      require_property vpp_worker0_core 1 "$RESULT_DIR/s187-status.${label}.properties"
      require_property vpp_worker1_core 2 "$RESULT_DIR/s187-status.${label}.properties"
      require_property worker_core_config_match true \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property product_graph_worker_count 2 \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property product_graph_worker_layout_ready true \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property placement_fixed_before_start true \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property dynamic_worker_change false \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_property threshold_scope engineering_guardrail_not_release_slo \
        "$RESULT_DIR/s187-status.${label}.properties"
      require_numeric_positive generation "$RESULT_DIR/s187-status.${label}.properties"
      return
    fi
    if grep -Fq "state=error" "$RESULT_DIR/snapshot.${label}.properties"; then
      break
    fi
    if (( SECONDS >= next_start_retry )); then
      start_profile "$profile"
      next_start_retry=$((SECONDS + 10))
    fi
    sleep 1
  done
  fail_closed "$label did not reach running ${profile}/${adapter}"
}

wait_for_stopped() {
  local label="$1"
  local deadline=$((SECONDS + 50))
  while (( SECONDS < deadline )); do
    snapshot_to_file "$label"
    if grep -Fxq "mayBeActive=false" "$RESULT_DIR/snapshot.${label}.properties" \
        && { grep -Fxq "state=stopped" "$RESULT_DIR/snapshot.${label}.properties" \
          || grep -Fxq "state=error" "$RESULT_DIR/snapshot.${label}.properties"; }; then
      s187_status_to_file "$label"
      return
    fi
    sleep 1
  done
  fail_closed "$label did not reach inactive stopped/error state"
}

capture_product_processes() {
  local label="$1"
  root_shell 'pidof libvpp_runtime.so vpp 2>/dev/null || true' \
    > "$RESULT_DIR/product-pids.${label}.txt" 2>&1 || true
}

process_count() {
  local file="$1"
  awk '
    /^[0-9]+([[:space:]][0-9]+)*[[:space:]]*$/ {
      count += NF
    }
    END { print count + 0 }' "$file"
}

single_product_pid() {
  local label="$1"
  local count deadline
  deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    capture_product_processes "$label"
    count="$(process_count "$RESULT_DIR/product-pids.${label}.txt")"
    [[ "$count" == 1 ]] && break
    sleep 1
  done
  [[ "$count" == 1 ]] || fail_closed "$label expected exactly one Product Core process, got $count"
  awk '
    /^[0-9]+([[:space:]][0-9]+)*[[:space:]]*$/ {
      for (i = 1; i <= NF; i++) {
        print $i
        exit
      }
    }' "$RESULT_DIR/product-pids.${label}.txt"
}

assert_product_process_count() {
  local label="$1"
  local expected="$2"
  local count deadline
  deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    capture_product_processes "$label"
    count="$(process_count "$RESULT_DIR/product-pids.${label}.txt")"
    [[ "$count" == "$expected" ]] && return
    sleep 1
  done
  [[ "$count" == "$expected" ]] \
    || fail_closed "$label expected $expected Product Core process(es), got $count"
}

capture_root_hooks() {
  local label="$1"
  root_shell 'for tool in iptables ip6tables; do echo TOOL=$tool; $tool -w -t mangle -S OUTPUT 2>&1 | grep -F SAKAMOTO_PRODUCT || true; $tool -w -t mangle -S INPUT 2>&1 | grep -F SAKAMOTO_PRODUCT || true; $tool -w -t mangle -S SAKAMOTO_PRODUCT_S176_OUTPUT 2>&1 || true; $tool -w -t mangle -S SAKAMOTO_PRODUCT_S178_INPUT 2>&1 || true; done' \
    > "$RESULT_DIR/root-hooks.${label}.txt" 2>&1 || true
}

root_hooks_present() {
  local label="$1"
  grep -Fq "$ROOT_OUTPUT_CHAIN" "$RESULT_DIR/root-hooks.${label}.txt" \
    || return 1
  grep -Fq "$ROOT_INPUT_CHAIN" "$RESULT_DIR/root-hooks.${label}.txt"
}

assert_root_hooks_present() {
  local label="$1"
  capture_root_hooks "$label"
  root_hooks_present "$label" \
    || fail_closed "$label did not show Root NFQUEUE hooks"
}

assert_no_root_hooks() {
  local label="$1"
  capture_root_hooks "$label"
  if grep -Fq "SAKAMOTO_PRODUCT" "$RESULT_DIR/root-hooks.${label}.txt"; then
    fail_closed "$label still has Root NFQUEUE hook residue"
  fi
}

capture_vpn_connectivity() {
  local label="$1"
  adb_target shell dumpsys connectivity > "$RESULT_DIR/connectivity.${label}.txt" 2>&1 || true
}

vpn_present() {
  local label="$1"
  grep -Eq "VPN:${PACKAGE}" "$RESULT_DIR/connectivity.${label}.txt" \
    && grep -Eq "InterfaceName: tun0" "$RESULT_DIR/connectivity.${label}.txt"
}

assert_vpn_present() {
  local label="$1"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    capture_vpn_connectivity "$label"
    if vpn_present "$label"; then
      return
    fi
    sleep 1
  done
  fail_closed "$label did not show active VPN/tun0"
}

assert_no_vpn_residue() {
  local label="$1"
  capture_vpn_connectivity "$label"
  if vpn_present "$label"; then
    fail_closed "$label still has VPN/tun0 residue"
  fi
}

capture_profile_dirs() {
  local label="$1"
  local output="$RESULT_DIR/profile-dirs.${label}.properties"
  : > "$output"
  # A profile is present only when Product Core runtime sentinels remain.
  # Empty profile parent directories can be recreated by the app after a cold
  # start/stop and are not residue.
  if adb_target shell run-as "$PACKAGE" ls \
      "${ROOT_PROFILE_PATH}/owner.properties" \
      "${ROOT_PROFILE_PATH}/startup.conf" \
      "${ROOT_PROFILE_PATH}/runtime" \
      "${ROOT_PROFILE_PATH}/logs" \
      "${ROOT_PROFILE_PATH}/shm" >/dev/null 2>&1; then
    printf 'root_profile=present\n' >> "$output"
  else
    printf 'root_profile=absent\n' >> "$output"
  fi
  if adb_target shell run-as "$PACKAGE" ls \
      "${VPN_PROFILE_PATH}/owner.properties" \
      "${VPN_PROFILE_PATH}/startup.conf" \
      "${VPN_PROFILE_PATH}/runtime" \
      "${VPN_PROFILE_PATH}/logs" \
      "${VPN_PROFILE_PATH}/shm" >/dev/null 2>&1; then
    printf 'vpn_profile=present\n' >> "$output"
  else
    printf 'vpn_profile=absent\n' >> "$output"
  fi
}

assert_profile_dirs() {
  local label="$1"
  local root_expected="$2"
  local vpn_expected="$3"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    capture_profile_dirs "$label"
    if grep -Fxq "root_profile=${root_expected}" \
        "$RESULT_DIR/profile-dirs.${label}.properties" \
        && grep -Fxq "vpn_profile=${vpn_expected}" \
          "$RESULT_DIR/profile-dirs.${label}.properties"; then
      return
    fi
    sleep 1
  done
  fail_closed "$label profile residue did not settle to root=${root_expected} vpn=${vpn_expected}"
}

capture_startup_conf() {
  local label="$1"
  local profile="$2"
  read_app_file "files/profiles/${profile}/vpp/startup.conf" \
    > "$RESULT_DIR/startup.${label}.conf"
  grep -Fq 'cpu {' "$RESULT_DIR/startup.${label}.conf" \
    || fail_closed "$label startup.conf missing CPU placement block"
  grep -Fq 'main-core 0' "$RESULT_DIR/startup.${label}.conf" \
    || fail_closed "$label startup.conf missing fixed main-core 0"
  grep -Fq 'corelist-workers 1-2' "$RESULT_DIR/startup.${label}.conf" \
    || fail_closed "$label startup.conf missing fixed worker cores 1-2"
  if grep -Eq '(^|[[:space:]])workers[[:space:]]+[0-9]' \
      "$RESULT_DIR/startup.${label}.conf"; then
    fail_closed "$label startup.conf used auto worker count instead of fixed corelist"
  fi
  kv "${label}.main_core_configured" 0
  kv "${label}.worker_count_configured" 2
  kv "${label}.worker_cores_configured" 1-2
}

assert_placement_static() {
  local label="$1"
  local before="$2"
  local after="$3"
  local key
  for key in generation main_core worker_count worker_cores vpp_main_core \
      vpp_worker_count vpp_worker0_core vpp_worker1_core worker_core_config_match \
      product_graph_worker_count product_graph_hash_seed owner_mapping \
      owner_mapping_seed; do
    local old_value new_value
    old_value="$(property_value "$key" "$before")"
    new_value="$(property_value "$key" "$after")"
    [[ -n "$old_value" && "$old_value" == "$new_value" ]] \
      || fail_closed "$label changed $key from $old_value to $new_value"
  done
  kv "${label}.placement_static" true
}

proc_ticks() {
  local label="$1"
  local pid="$2"
  local ticks
  ticks="$(root_shell "awk '{ print \$14 + \$15 }' /proc/$pid/stat 2>/dev/null" \
    | tr -d '\r\n' || true)"
  [[ "$ticks" =~ ^[0-9]+$ ]] \
    || fail_closed "$label could not read proc ticks for pid $pid"
  printf '%s\n' "$ticks"
}

cpu_pct() {
  local ticks0="$1"
  local ticks1="$2"
  local seconds="$3"
  local tick_hz
  tick_hz="$(adb_target shell getconf CLK_TCK 2>/dev/null | tr -d '\r\n' || printf '100')"
  python3 - "$ticks0" "$ticks1" "$tick_hz" "$seconds" <<'PY'
import sys
t0, t1, hz, sec = map(float, sys.argv[1:])
print(f"{max(0.0, (t1 - t0) * 100.0 / max(1.0, hz * sec)):.2f}")
PY
}

capture_proc_metrics() {
  local label="$1"
  local pid="$2"
  local output="$RESULT_DIR/proc.${label}.properties"
  [[ "$pid" =~ ^[0-9]+$ ]] || fail_closed "$label product pid is not numeric: $pid"
  root_shell "pid=$pid; test -d /proc/\$pid || exit 1; \
echo pid=\$pid; \
echo fd_count=\$(ls -1 /proc/\$pid/fd 2>/dev/null | wc -l); \
echo thread_count=\$(ls -1 /proc/\$pid/task 2>/dev/null | wc -l); \
awk '/^VmRSS:/ { print \"rss_kb=\" \$2 } /^Cpus_allowed_list:/ { print \"main_cpus_allowed_list=\" \$2 } /^Threads:/ { print \"status_threads=\" \$2 }' /proc/\$pid/status; \
for task in /proc/\$pid/task/*; do \
  tid=\${task##*/}; \
  allowed=\$(awk '/^Cpus_allowed_list:/ { print \$2 }' \"\$task/status\" 2>/dev/null); \
  name=\$(cat \"\$task/comm\" 2>/dev/null); \
  printf 'task_%s_name=%s\n' \"\$tid\" \"\$name\"; \
  printf 'task_%s_cpus_allowed_list=%s\n' \"\$tid\" \"\$allowed\"; \
done" > "$output" \
    || fail_closed "$label could not capture proc metrics for pid $pid"
  grep -Eq '^task_[0-9]+_cpus_allowed_list=0$' "$output" \
    || fail_closed "$label did not show a main thread pinned to core 0"
  grep -Eq '^task_[0-9]+_cpus_allowed_list=1$' "$output" \
    || fail_closed "$label did not show a worker thread pinned to core 1"
  grep -Eq '^task_[0-9]+_cpus_allowed_list=2$' "$output" \
    || fail_closed "$label did not show a worker thread pinned to core 2"
  local fd_count thread_count rss_kb
  fd_count="$(property_value fd_count "$output")"
  thread_count="$(property_value thread_count "$output")"
  rss_kb="$(property_value rss_kb "$output")"
  require_numeric_le "${label}.fd_count" "$fd_count" "$S187_MAX_FD_COUNT"
  require_numeric_le "${label}.thread_count" "$thread_count" "$S187_MAX_THREAD_COUNT"
  require_numeric_le "${label}.rss_kb" "$rss_kb" "$S187_MAX_RSS_KB"
  kv "${label}.fd_count" "$fd_count"
  kv "${label}.thread_count" "$thread_count"
  kv "${label}.rss_kb" "$rss_kb"
}

sample_idle_cpu() {
  local profile="$1"
  local pid="$2"
  local ticks0 ticks1 pct
  ticks0="$(proc_ticks "${profile}.idle.before" "$pid")"
  sleep "$S187_IDLE_SEC"
  ticks1="$(proc_ticks "${profile}.idle.after" "$pid")"
  pct="$(cpu_pct "$ticks0" "$ticks1" "$S187_IDLE_SEC")"
  {
    printf 'pid=%s\n' "$pid"
    printf 'ticks.before=%s\n' "${ticks0:-0}"
    printf 'ticks.after=%s\n' "${ticks1:-0}"
    printf 'cpuPct=%s\n' "$pct"
  } > "$RESULT_DIR/${profile}.idle-cpu.properties"
  require_numeric_le "${profile}.idle.cpuPct" "$pct" "$S187_MAX_IDLE_CPU_PCT"
  kv "${profile}.idle.cpuPct" "$pct"
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

start_echo_server() {
  local proto="$1"
  local family="$2"
  local bind_host="$3"
  local listen_port="$4"
  local expected_nonce="$5"
  local ready_file="$6"
  local log_file="$7"
  python3 - "$proto" "$family" "$bind_host" "$listen_port" \
    "$expected_nonce" "$ready_file" "$log_file" <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

proto = sys.argv[1]
family = socket.AF_INET6 if sys.argv[2] == "6" else socket.AF_INET
host = sys.argv[3]
port = int(sys.argv[4])
expected = sys.argv[5].encode()
ready = pathlib.Path(sys.argv[6])
log = pathlib.Path(sys.argv[7])
result = f"{proto}_echo_unseen"
peer = ""
request_bytes = 0
response_bytes = 0
nonce = ""
try:
    if proto == "udp":
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        sock.settimeout(30)
        ready.write_text("ready\n", encoding="utf-8")
        data, address = sock.recvfrom(4096)
        peer = str(address)
        request_bytes = len(data)
        nonce = data.decode(errors="replace")
        if data == expected:
            sock.sendto(data, address)
            response_bytes = len(data)
            result = "udp_echo_matched"
        else:
            result = "udp_echo_mismatch"
        sock.close()
    else:
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(30)
        ready.write_text("ready\n", encoding="utf-8")
        conn, address = server.accept()
        peer = str(address)
        with conn:
            conn.settimeout(10)
            data = bytearray()
            while len(data) < len(expected):
                chunk = conn.recv(len(expected) - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            request_bytes = len(data)
            nonce = bytes(data).decode(errors="replace")
            if bytes(data) == expected:
                conn.sendall(data)
                response_bytes = len(data)
                result = "tcp_echo_matched"
            else:
                result = "tcp_echo_mismatch"
        server.close()
except Exception as error:
    result = f"{proto}_echo_failed:{error.__class__.__name__}:{error}"
finally:
    log.write_text(
        f"family={'AF_INET6' if family == socket.AF_INET6 else 'AF_INET'}\n"
        f"result={result}\npeer={peer}\nrequestBytes={request_bytes}\n"
        f"responseBytes={response_bytes}\nnonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

wait_probe_result() {
  local relative="$1"
  local expected_nonce="$2"
  local expected_result="$3"
  local out_file="$4"
  local deadline="${5:-$((SECONDS + 45))}"
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "nonce=${expected_nonce}" "$out_file" \
        && grep -Fq "result=${expected_result}" "$out_file"; then
      return 0
    fi
    if grep -Fq "nonce=${expected_nonce}" "$out_file" \
        && grep -Fxq "bindResult=vpn_network_not_found" "$out_file"; then
      return 2
    fi
    sleep 1
  done
  return 1
}

require_app_probe() {
  local probe_file="$1"
  local label="$2"
  local bind_to_vpn="$3"
  require_property bindToVpn "$bind_to_vpn" "$probe_file"
  if [[ "$bind_to_vpn" == true ]]; then
    require_property bindResult bound "$probe_file"
  else
    require_property bindResult not_requested "$probe_file"
  fi
  local uid request_bytes response_bytes
  uid="$(property_value uid "$probe_file")"
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || [[ "$uid" == "2000" ]]; then
    fail_closed "$label did not run as installed app uid"
  fi
  request_bytes="$(property_value requestBytes "$probe_file")"
  response_bytes="$(property_value responseBytes "$probe_file")"
  if ! [[ "$request_bytes" =~ ^[0-9]+$ ]] || (( request_bytes <= 0 )); then
    fail_closed "$label did not write request bytes"
  fi
  if [[ "$response_bytes" != "$request_bytes" ]]; then
    fail_closed "$label response bytes did not match request bytes"
  fi
  kv "${label}.uid" "$uid"
}

start_probe_activity() {
  local proto="$1"
  local target_host="$2"
  local port="$3"
  local nonce="$4"
  local bind_to_vpn="$5"
  if [[ "$proto" == udp ]]; then
    start_activity --ez debugUdpTraffic true --es debugUdpHost "$target_host" \
      --ei debugUdpPort "$port" --es debugUdpNonce "$nonce" \
      --ez debugUdpExpectReply true --ei debugUdpTimeoutMillis "$timeout_ms" \
      --ez debugTrafficBindToVpn "$bind_to_vpn"
  else
    start_activity --ez debugTraffic true --es debugTrafficHost "$target_host" \
      --ei debugTrafficPort "$port" --es debugTrafficNonce "$nonce" \
      --ei debugTrafficTimeoutMillis "$timeout_ms" \
      --ez debugTrafficBindToVpn "$bind_to_vpn"
  fi
}

run_probe() {
  local profile="$1"
  local label="$2"
  local proto="$3"
  local family="$4"
  local target_host="$5"
  local port="$6"
  local bind_to_vpn="$7"
  local nonce="s187-${profile}-${label}-${RUN_ID}"
  local bind_host ready_file log_file probe_path probe_file expected start_ms end_ms latency_ms
  local deadline probe_status retry_count
  bind_host="0.0.0.0"
  [[ "$family" == 6 ]] && bind_host="$target_host"
  ready_file="$RESULT_DIR/${nonce}.ready"
  log_file="$RESULT_DIR/${nonce}.server.properties"
  probe_path="$TCP_PROBE_PATH"
  expected="tcp_echo_matched"
  if [[ "$proto" == udp ]]; then
    probe_path="$UDP_PROBE_PATH"
    expected="udp_echo_matched"
  fi
  probe_file="$RESULT_DIR/${nonce}.probe.properties"
  rm -f "$ready_file" "$log_file" "$probe_file"
  server_pid=""
  start_echo_server "$proto" "$family" "$bind_host" "$port" "$nonce" \
    "$ready_file" "$log_file"
  wait_for_host_ready "$ready_file" || fail_closed "$label server did not become ready"
  start_ms="$(now_ms)"
  deadline=$((SECONDS + 45))
  retry_count=0
  while (( SECONDS < deadline )); do
    adb_target shell run-as "$PACKAGE" rm -f "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
      >/dev/null 2>&1 || true
    start_probe_activity "$proto" "$target_host" "$port" "$nonce" "$bind_to_vpn"
    probe_status=0
    wait_probe_result "$probe_path" "$nonce" "$expected" "$probe_file" "$deadline" \
      || probe_status=$?
    if (( probe_status == 0 )); then
      break
    fi
    if (( probe_status == 2 )) && [[ "$bind_to_vpn" == true ]]; then
      retry_count=$((retry_count + 1))
      kv "${profile}.${label}.vpn_network_retry" "$retry_count"
      sleep 1
      continue
    fi
    fail_closed "$profile $label installed-app probe did not echo"
  done
  [[ "$probe_status" == 0 ]] \
    || fail_closed "$profile $label installed-app probe did not echo"
  finish_server
  require_property result "$expected" "$log_file"
  require_app_probe "$probe_file" "${profile}.${label}" "$bind_to_vpn"
  end_ms="$(now_ms)"
  latency_ms=$((end_ms - start_ms))
  require_numeric_le "${profile}.${label}.latencyMs" \
    "$latency_ms" "$S187_MAX_PROBE_LATENCY_MS"
  kv "${profile}.${label}.latencyMs" "$latency_ms"
}

sample_active_load() {
  local profile="$1"
  local pid="$2"
  local bind_to_vpn="$3"
  local port_base="$4"
  local ticks0 ticks1 pct elapsed_start elapsed_end elapsed_sec
  ticks0="$(proc_ticks "${profile}.active.before" "$pid")"
  elapsed_start="$(now_ms)"
  run_probe "$profile" tcp4 tcp 4 "$host4" "$port_base" "$bind_to_vpn"
  run_probe "$profile" udp4 udp 4 "$host4" "$((port_base + 1))" "$bind_to_vpn"
  run_probe "$profile" tcp6 tcp 6 "$host6" "$((port_base + 2))" "$bind_to_vpn"
  run_probe "$profile" udp6 udp 6 "$host6" "$((port_base + 3))" "$bind_to_vpn"
  elapsed_end="$(now_ms)"
  ticks1="$(proc_ticks "${profile}.active.after" "$pid")"
  elapsed_sec="$(python3 - "$elapsed_start" "$elapsed_end" <<'PY'
import sys
start, end = map(int, sys.argv[1:])
print(max(0.001, (end - start) / 1000.0))
PY
)"
  pct="$(cpu_pct "$ticks0" "$ticks1" "$elapsed_sec")"
  {
    printf 'pid=%s\n' "$pid"
    printf 'ticks.before=%s\n' "${ticks0:-0}"
    printf 'ticks.after=%s\n' "${ticks1:-0}"
    printf 'elapsedSec=%s\n' "$elapsed_sec"
    printf 'cpuPct=%s\n' "$pct"
  } > "$RESULT_DIR/${profile}.active-cpu.properties"
  require_numeric_le "${profile}.active.cpuPct" "$pct" "$S187_MAX_ACTIVE_CPU_PCT"
  kv "${profile}.active.cpuPct" "$pct"
  kv "${profile}.dual_stack_tcp_udp_load" true
}

read_status_after_refresh() {
  local label="$1"
  local relative="$2"
  local out="$3"
  local deadline=$((SECONDS + 20))
  refresh_product_status
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out"
    if [[ -s "$out" ]]; then
      return 0
    fi
    sleep 1
  done
  fail_closed "$label status was not published"
}

require_root_status_after_load() {
  local out="$RESULT_DIR/root-status.after-load.properties"
  read_status_after_refresh root "$ROOT_STATUS_PATH" "$out"
  require_numeric_positive tcp_packets "$out"
  require_numeric_positive udp_packets "$out"
  require_numeric_positive ipv4_packets "$out"
  require_numeric_positive ipv6_packets "$out"
  require_numeric_positive buffer_returns "$out"
}

require_vpn_status_after_load() {
  local out="$RESULT_DIR/vpn-status.after-load.properties"
  read_status_after_refresh vpn "$VPN_STATUS_PATH" "$out"
  require_numeric_positive vpn_tun_udp4_tun_origin_packets "$out"
  require_numeric_positive vpn_tun_udp6_tun_origin_packets "$out"
  require_numeric_positive vpn_tun_tcp4_tun_origin_packets "$out"
  require_numeric_positive vpn_tun_tcp6_tun_origin_packets "$out"
  require_numeric_positive vpn_flow_stack_return_provenance_packets "$out"
  require_numeric_positive vpn_tun_write_completions "$out"
}

adb_devices_contains_serial() {
  local attempt output
  for attempt in 1 2 3 4 5 6 7 8; do
    output="$("$ADB" devices 2>"$RESULT_DIR/adb-devices.${attempt}.stderr" \
      | tr -d '\r' || true)"
    printf '%s\n' "$output" > "$RESULT_DIR/adb-devices.${attempt}.txt"
    if printf '%s\n' "$output" | grep -Eq "^${serial}[[:space:]]+device$"; then
      kv adb_devices_attempt "$attempt"
      return 0
    fi
    sleep 1
  done
  return 1
}

kv acceptance SAKAMOTO-187-worker-core-guardrails
kv serial "$serial"
kv package "$PACKAGE"
kv owner_token_env_key "$OWNER_TOKEN_ENV_KEY"
kv host4 "$host4"
kv host6 "$host6"
acquire_run_lock
write_thresholds

adb_devices_contains_serial \
  || fail_closed "controlled Pixel 6a serial is not in adb devices"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt" \
  || fail_closed "connected serial is not the controlled Pixel 6a"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
root_uid="$(root_shell 'id -u' 2>/dev/null || true)"
[[ "$root_uid" == "0" ]] || fail_closed "KernelSU/root authorization is unavailable"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true
adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
kv preflight_force_stop_after_install true

stop_runtime
wait_for_stopped preflight
assert_no_root_hooks preflight
assert_no_vpn_residue preflight
assert_product_process_count preflight 0
assert_profile_dirs preflight absent absent
clear_app_files
kv preflight_zero_residue true

start_profile root
wait_for_running root_start root root-nfqueue
assert_root_hooks_present root_start
assert_no_vpn_residue root_start
assert_product_process_count root_start 1
assert_profile_dirs root_start present absent
capture_startup_conf root_start root
root_pid="$(single_product_pid root_start)"
capture_proc_metrics root.before "$root_pid"
sample_idle_cpu root "$root_pid"
s187_status_to_file root.before
sample_active_load root "$root_pid" false "$base_port"
read_status_after_refresh root-s187 "$STATUS_PATH" "$RESULT_DIR/s187-status.root.after.properties"
assert_placement_static root \
  "$RESULT_DIR/s187-status.root.before.properties" \
  "$RESULT_DIR/s187-status.root.after.properties"
capture_proc_metrics root.after "$root_pid"
require_root_status_after_load

start_profile vpn
wait_for_running vpn_start vpn vpn-tun-hev-lwip
assert_no_root_hooks vpn_start
assert_vpn_present vpn_start
assert_product_process_count vpn_start 1
assert_profile_dirs vpn_start absent present
capture_startup_conf vpn_start vpn
vpn_pid="$(single_product_pid vpn_start)"
capture_proc_metrics vpn.before "$vpn_pid"
sample_idle_cpu vpn "$vpn_pid"
s187_status_to_file vpn.before
sample_active_load vpn "$vpn_pid" true "$((base_port + 10))"
read_status_after_refresh vpn-s187 "$STATUS_PATH" "$RESULT_DIR/s187-status.vpn.after.properties"
assert_placement_static vpn \
  "$RESULT_DIR/s187-status.vpn.before.properties" \
  "$RESULT_DIR/s187-status.vpn.after.properties"
capture_proc_metrics vpn.after "$vpn_pid"
require_vpn_status_after_load

start_profile root
wait_for_running root_after_vpn_switch root root-nfqueue
assert_root_hooks_present root_after_vpn_switch
assert_no_vpn_residue root_after_vpn_switch
assert_product_process_count root_after_vpn_switch 1
assert_profile_dirs root_after_vpn_switch present absent
kv short_switch_vpn_to_root true

stop_runtime
wait_for_stopped final
assert_no_root_hooks final
assert_no_vpn_residue final
assert_product_process_count final 0
assert_profile_dirs final absent absent
kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-187 worker/core guardrails: PASS"
