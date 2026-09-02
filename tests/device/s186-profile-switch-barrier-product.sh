#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-186 Root -> VPN -> Root Product Core switch barrier acceptance.
#
# PASS means the installed debug APK performs profile replacement through the
# RuntimeService Product Core lifecycle, never by runner-side stop/start
# substitution: cleanup failure blocks replacement, a clean Root->VPN switch
# removes Root process/hook/profile residue before VPN is running, a clean
# VPN->Root switch removes VPN TUN/profile residue before Root is running, stale
# VPN fault events do not mutate the Root replacement, and final stop leaves no
# Product Core, Root hook, VPN, or profile residue.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S186_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s186-profile-switch-barrier}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly RUNTIME_LOG_PATH="files/logs/runtime-service.log"
readonly STATUS_PATH="files/product-state/s186-profile-switch-barrier.properties"
readonly ROOT_STATUS_PATH="files/product-state/s179-root-fault-recovery.properties"
readonly VPN_STATUS_PATH="files/product-state/s185-vpn-fault-recovery.properties"
readonly S180_STATUS_PATH="files/product-state/s180-vpn-udp4-direct-egress.properties"
readonly S181_STATUS_PATH="files/product-state/s181-vpn-tcp4-direct-egress.properties"
readonly S182_STATUS_PATH="files/product-state/s182-vpn-udp6-direct-egress.properties"
readonly S183_STATUS_PATH="files/product-state/s183-vpn-tcp6-direct-egress.properties"
readonly S184_STATUS_PATH="files/product-state/s184-vpn-network-epoch.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"
readonly ROOT_PROFILE_PATH="files/profiles/root/vpp"
readonly VPN_PROFILE_PATH="files/profiles/vpn/vpp"
readonly ROOT_OUTPUT_CHAIN="SAKAMOTO_PRODUCT_S176_OUTPUT"
readonly ROOT_INPUT_CHAIN="SAKAMOTO_PRODUCT_S178_INPUT"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s186-profile-switch-barrier-product.sh --run

Optional:
  --serial 28201JEGR0XPAJ

Before running, grant this debug APK root permission in KernelSU Manager and
approve it as an Android VPN service. Device PASS is the only PASS.
EOF
}

serial="$S186_SERIAL"
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

if [[ "$serial" != "$S186_SERIAL" ]]; then
  echo "SAKAMOTO-186 only accepts controlled Pixel 6a serial $S186_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  if declare -F dump_diagnostics >/dev/null; then
    dump_diagnostics failure >/dev/null 2>&1 || true
  fi
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-186 FAIL: $1" >&2
  exit 1
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
  adb_target shell "su 0 sh -c $quoted" | tr -d '\r'
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
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
    }
  ' "$file"
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

start_activity() {
  local attempt
  for attempt in 1 2 3 4 5 6 7 8; do
    if adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
        >> "$RESULT_DIR/am-start.log" 2>&1; then
      return 0
    fi
    printf 'am_start_retry=%s\n' "$attempt" >> "$RESULT_DIR/am-start.log"
    sleep 1
  done
  fail_closed "am start failed after 8 retries; see $RESULT_DIR/am-start.log"
}

# stop_runtime uses a headless Activity that finishes after delivering its
# request.  Cold-start the first profile command after the zero-residue
# preflight so a finishing Activity cannot consume the next start intent.
cold_start_control_activity() {
  adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 2
}

clear_evidence_files() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$ROOT_STATUS_PATH" "$VPN_STATUS_PATH" \
    "$S180_STATUS_PATH" "$S181_STATUS_PATH" "$S182_STATUS_PATH" \
    "$S183_STATUS_PATH" "$S184_STATUS_PATH" "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
    >/dev/null 2>&1 || true
}

snapshot_to_file() {
  local label="$1"
  read_app_file "$STATE_PATH" > "$RESULT_DIR/snapshot.${label}.properties"
}

s186_status_to_file() {
  local label="$1"
  read_app_file "$STATUS_PATH" > "$RESULT_DIR/s186-status.${label}.properties"
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
  adb_target shell dumpsys connectivity \
    > "$RESULT_DIR/connectivity.${label}.txt" 2>&1 || true
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

capture_product_processes() {
  local label="$1"
  root_shell 'pidof libvpp_runtime.so vpp 2>/dev/null || true' \
    > "$RESULT_DIR/product-pids.${label}.txt" 2>&1 || true
}

process_count() {
  local file="$1"
  tr ' \t' '\n' < "$file" | awk '/^[0-9]+$/ { count++ } END { print count + 0 }'
}

assert_product_process_count() {
  local label="$1"
  local expected="$2"
  capture_product_processes "$label"
  local count
  count="$(process_count "$RESULT_DIR/product-pids.${label}.txt")"
  [[ "$count" == "$expected" ]] \
    || fail_closed "$label expected $expected Product Core process(es), got $count"
}

assert_product_process_count_at_most_one() {
  local label="$1"
  capture_product_processes "$label"
  local count
  count="$(process_count "$RESULT_DIR/product-pids.${label}.txt")"
  (( count <= 1 )) \
    || fail_closed "$label saw more than one Product Core process"
}

assert_pid_absent_after_switch() {
  local old_file="$1"
  local new_file="$2"
  local old_pid
  for old_pid in $(tr ' \t' '\n' < "$old_file" | awk '/^[0-9]+$/'); do
    if grep -Fwq "$old_pid" "$new_file"; then
      fail_closed "old Product Core pid $old_pid remained after switch"
    fi
  done
}

capture_profile_dirs() {
  local label="$1"
  local output="$RESULT_DIR/profile-dirs.${label}.properties"
  : > "$output"
  if adb_target shell run-as "$PACKAGE" test -d "$ROOT_PROFILE_PATH" \
      >/dev/null 2>&1; then
    printf 'root_profile=present\n' >> "$output"
  else
    printf 'root_profile=absent\n' >> "$output"
  fi
  if adb_target shell run-as "$PACKAGE" test -d "$VPN_PROFILE_PATH" \
      >/dev/null 2>&1; then
    printf 'vpn_profile=present\n' >> "$output"
  else
    printf 'vpn_profile=absent\n' >> "$output"
  fi
}

assert_profile_dirs() {
  local label="$1"
  local root_expected="$2"
  local vpn_expected="$3"
  local deadline=$((SECONDS + 10))
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
  capture_profile_dirs "$label"
  require_property root_profile "$root_expected" "$RESULT_DIR/profile-dirs.${label}.properties"
  require_property vpn_profile "$vpn_expected" "$RESULT_DIR/profile-dirs.${label}.properties"
}

assert_no_mixed_resources() {
  local label="$1"
  assert_product_process_count_at_most_one "$label"
  capture_root_hooks "$label"
  capture_vpn_connectivity "$label"
  if root_hooks_present "$label" && vpn_present "$label"; then
    fail_closed "$label has mixed Root hooks and VPN/tun0 resources"
  fi
}

zero_residue_observed() {
  local label="$1"
  snapshot_to_file "$label"
  s186_status_to_file "$label"
  capture_root_hooks "$label"
  capture_vpn_connectivity "$label"
  capture_product_processes "$label"
  capture_profile_dirs "$label"
  grep -Fxq "state=stopped" "$RESULT_DIR/snapshot.${label}.properties" \
    || return 1
  grep -Fxq "mayBeActive=false" "$RESULT_DIR/snapshot.${label}.properties" \
    || return 1
  if grep -Fq "SAKAMOTO_PRODUCT" "$RESULT_DIR/root-hooks.${label}.txt"; then
    return 1
  fi
  if vpn_present "$label"; then
    return 1
  fi
  [[ "$(process_count "$RESULT_DIR/product-pids.${label}.txt")" == 0 ]] \
    || return 1
  grep -Fxq "root_profile=absent" \
    "$RESULT_DIR/profile-dirs.${label}.properties" || return 1
  grep -Fxq "vpn_profile=absent" \
    "$RESULT_DIR/profile-dirs.${label}.properties" || return 1
  return 0
}

wait_for_zero_residue() {
  local label="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    if zero_residue_observed "$label"; then
      return
    fi
    sleep 1
  done
  fail_closed "$label did not reach stopped zero-residue"
}

dump_diagnostics() {
  local label="$1"
  read_app_file "$STATE_PATH" > "$RESULT_DIR/snapshot.${label}.current.properties" || true
  read_app_file "$STATUS_PATH" > "$RESULT_DIR/s186-status.${label}.current.properties" || true
  read_app_file "$RUNTIME_LOG_PATH" > "$RESULT_DIR/runtime-service.${label}.log" || true
  capture_root_hooks "$label" || true
  capture_vpn_connectivity "$label" || true
  capture_product_processes "$label" || true
  capture_profile_dirs "$label" || true
}

wait_for_running() {
  local label="$1"
  local profile="$2"
  local adapter="$3"
  local deadline=$((SECONDS + 90))
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
      s186_status_to_file "$label"
      require_property schema s186-profile-switch-barrier/v1 \
        "$RESULT_DIR/s186-status.${label}.properties"
      require_property profile "$profile" "$RESULT_DIR/s186-status.${label}.properties"
      require_property state running "$RESULT_DIR/s186-status.${label}.properties"
      require_property adapterReadiness "$adapter" \
        "$RESULT_DIR/s186-status.${label}.properties"
      require_numeric_positive generation "$RESULT_DIR/s186-status.${label}.properties"
      return
    fi
    if grep -Fq "state=error" "$RESULT_DIR/snapshot.${label}.properties"; then
      break
    fi
    sleep 1
  done
  fail_closed "$label did not reach running ${profile}/${adapter}"
}

wait_for_error() {
  local label="$1"
  local error_code="$2"
  local may_be_active="$3"
  local deadline=$((SECONDS + 40))
  while (( SECONDS < deadline )); do
    snapshot_to_file "$label"
    if grep -Fxq "state=error" "$RESULT_DIR/snapshot.${label}.properties" \
        && grep -Fxq "errorCode=${error_code}" \
          "$RESULT_DIR/snapshot.${label}.properties" \
        && grep -Fxq "mayBeActive=${may_be_active}" \
          "$RESULT_DIR/snapshot.${label}.properties"; then
      s186_status_to_file "$label"
      require_property schema s186-profile-switch-barrier/v1 \
        "$RESULT_DIR/s186-status.${label}.properties"
      require_property state error "$RESULT_DIR/s186-status.${label}.properties"
      require_property errorCode "$error_code" "$RESULT_DIR/s186-status.${label}.properties"
      require_property mayBeActive "$may_be_active" \
        "$RESULT_DIR/s186-status.${label}.properties"
      return
    fi
    sleep 1
  done
  fail_closed "$label did not publish error ${error_code}"
}

wait_for_stopped() {
  local label="$1"
  local deadline=$((SECONDS + 40))
  while (( SECONDS < deadline )); do
    snapshot_to_file "$label"
    if grep -Fxq "state=stopped" "$RESULT_DIR/snapshot.${label}.properties" \
        && grep -Fxq "mayBeActive=false" \
          "$RESULT_DIR/snapshot.${label}.properties"; then
      s186_status_to_file "$label"
      return
    fi
    sleep 1
  done
  fail_closed "$label did not reach stopped/mayBeActive=false"
}

generation_of() {
  local label="$1"
  property_value generation "$RESULT_DIR/snapshot.${label}.properties"
}

require_generation_after() {
  local name="$1"
  local newer="$2"
  local older="$3"
  [[ "$newer" =~ ^[0-9]+$ && "$older" =~ ^[0-9]+$ ]] \
    || fail_closed "$name generation is not numeric"
  (( newer > older )) || fail_closed "$name generation did not advance"
}

start_profile() {
  local profile="$1"
  start_activity --ez runtimeStart true --es runtimeProfile "$profile"
}

stop_runtime() {
  start_activity --ez runtimeCleanupFault false \
    --es runtimeRootNfqueueFaultMode none --es runtimeVpnFaultMode none \
    --ez runtimeStop true
}

kv acceptance SAKAMOTO-186-profile-switch-barrier
kv serial "$serial"
kv package "$PACKAGE"

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a serial is not in adb devices"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt" \
  || fail_closed "connected serial is not the controlled Pixel 6a"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
root_uid="$(root_shell 'id -u' 2>/dev/null || true)"
[[ "$root_uid" == "0" ]] || fail_closed "KernelSU/root authorization is unavailable"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true

stop_runtime
wait_for_zero_residue preflight
cold_start_control_activity
kv preflight_cold_start_settled true
clear_evidence_files
kv preflight_zero_residue true

start_profile root
wait_for_running cleanup_fault_root root root-nfqueue
assert_root_hooks_present cleanup_fault_root
assert_no_vpn_residue cleanup_fault_root
assert_product_process_count cleanup_fault_root 1
assert_profile_dirs cleanup_fault_root present absent
negative_root_generation="$(generation_of cleanup_fault_root)"
kv cleanup_fault_root_generation "$negative_root_generation"

start_activity --ez runtimeCleanupFault true
sleep 1
start_profile vpn
wait_for_error cleanup_fault_switch cleanup_failed true
assert_no_vpn_residue cleanup_fault_switch
assert_product_process_count_at_most_one cleanup_fault_switch
assert_profile_dirs cleanup_fault_switch present absent
kv cleanup_fault_blocks_replacement true

stop_runtime
wait_for_zero_residue cleanup_fault_cleared
kv cleanup_fault_cleared_zero_residue true

start_profile root
wait_for_running root_before_switch root root-nfqueue
assert_root_hooks_present root_before_switch
assert_no_vpn_residue root_before_switch
assert_product_process_count root_before_switch 1
assert_profile_dirs root_before_switch present absent
g_root1="$(generation_of root_before_switch)"
capture_product_processes root_before_switch
kv root_generation "$g_root1"

start_profile vpn
wait_for_running vpn_after_root_switch vpn vpn-tun-hev-lwip
assert_no_root_hooks vpn_after_root_switch
assert_vpn_present vpn_after_root_switch
assert_product_process_count vpn_after_root_switch 1
assert_no_mixed_resources vpn_after_root_switch
assert_profile_dirs vpn_after_root_switch absent present
g_vpn="$(generation_of vpn_after_root_switch)"
capture_product_processes vpn_after_root_switch
assert_pid_absent_after_switch "$RESULT_DIR/product-pids.root_before_switch.txt" \
  "$RESULT_DIR/product-pids.vpn_after_root_switch.txt"
require_generation_after root_to_vpn "$g_vpn" "$g_root1"
kv vpn_generation "$g_vpn"
kv switch_root_to_vpn true

start_profile root
wait_for_running root_after_vpn_switch root root-nfqueue
assert_root_hooks_present root_after_vpn_switch
assert_no_vpn_residue root_after_vpn_switch
assert_product_process_count root_after_vpn_switch 1
assert_no_mixed_resources root_after_vpn_switch
assert_profile_dirs root_after_vpn_switch present absent
g_root2="$(generation_of root_after_vpn_switch)"
capture_product_processes root_after_vpn_switch
assert_pid_absent_after_switch "$RESULT_DIR/product-pids.vpn_after_root_switch.txt" \
  "$RESULT_DIR/product-pids.root_after_vpn_switch.txt"
require_generation_after vpn_to_root "$g_root2" "$g_vpn"
kv root2_generation "$g_root2"
kv switch_vpn_to_root true

start_activity --es runtimeVpnFaultEvent revoke
sleep 1
start_activity --es runtimeVpnFaultEvent close_tun
sleep 1
start_activity --ez debugRefresh true
sleep 1
snapshot_to_file stale_vpn_events
require_property state running "$RESULT_DIR/snapshot.stale_vpn_events.properties"
require_property profile root "$RESULT_DIR/snapshot.stale_vpn_events.properties"
require_property generation "$g_root2" "$RESULT_DIR/snapshot.stale_vpn_events.properties"
require_property errorCode "" "$RESULT_DIR/snapshot.stale_vpn_events.properties"
assert_root_hooks_present stale_vpn_events
assert_no_vpn_residue stale_vpn_events
assert_product_process_count stale_vpn_events 1
kv stale_vpn_events_ignored true

stop_runtime
wait_for_zero_residue final

kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-186 profile switch barrier: PASS"
