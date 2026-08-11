#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-70 product RuntimeService profile lifecycle evidence matrix.
#
# Covers the product DebugControlActivity/RuntimeService path for clean
# Root↔VPN profile switch, user pause cleanup, Activity recreation survival,
# and a bounded cleanup-fault reason. Crash/reboot/Doze evidence is recorded
# separately before S70 is closed.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s70-profile-lifecycle-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
S70_BUILD_APK="${S70_BUILD_APK:-1}"
S70_INSTALL_APK="${S70_INSTALL_APK:-1}"
S70_CLEANUP_ON_EXIT="${S70_CLEANUP_ON_EXIT:-1}"
STATE_PATH="files/runtime-state/snapshot.properties"

mkdir -p "$RESULT_DIR"

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

read_snapshot() {
  adb_cmd shell run-as "$PACKAGE" cat "$STATE_PATH" 2>/dev/null | tr -d '\r' || true
}

snapshot_value_from() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

wait_for_snapshot() {
  local out_file="$1"
  local attempts="${2:-45}"
  shift 2
  local state=""
  for _ in $(seq 1 "$attempts"); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"$out_file"
    local matched=1
    local pattern
    for pattern in "$@"; do
      if ! grep -Fxq "$pattern" <<<"$state"; then
        matched=0
        break
      fi
    done
    if [[ "$matched" == "1" ]]; then
      printf '%s\n' "$state"
      return 0
    fi
    sleep 1
  done
  return 1
}

pid_alive() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || return 1
  adb_cmd shell su 0 sh -c "kill -0 $pid" >/dev/null 2>&1
}

assert_pid_gone() {
  local pid="$1"
  local out_file="$2"
  for _ in $(seq 1 20); do
    if ! pid_alive "$pid"; then
      printf 'pid=%s\nalive=false\n' "$pid" >"$out_file"
      return 0
    fi
    sleep 1
  done
  printf 'pid=%s\nalive=true\n' "$pid" >"$out_file"
  return 1
}

assert_no_tun0_residue() {
  local out_file="$1"
  if adb_cmd shell ip link show tun0 >"$out_file" 2>&1; then
    return 1
  fi
  return 0
}

assert_no_connectivity_residue() {
  local out_file="$1"
  adb_cmd shell dumpsys connectivity >"$out_file" 2>&1
  ! grep -Eq "VPN:${PACKAGE}|InterfaceName: tun0" "$out_file"
}

assert_no_native_residue() {
  local out_file="$1"
  local native=""
  native="$(adb_cmd shell pidof sucre-snortd libsucre_snortd.so libvpp_runtime.so vpp hev-socks5-tunnel 2>/dev/null \
    | tr -d '\r' || true)"
  printf '%s\n' "$native" >"$out_file"
  [[ -z "$native" ]]
}

disable_cleanup_fault() {
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeCleanupFault false >/dev/null 2>&1 || true
}

cleanup() {
  if [[ "$S70_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  disable_cleanup_fault
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_profile() {
  local profile="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile "$profile" \
    >"${out_dir}/start.intent.log" 2>&1
  wait_for_snapshot "${out_dir}/snapshot.running" 45 \
    "state=running" "profile=${profile}" "health=ok" "coreHealth=ok" \
    || {
      cat "${out_dir}/snapshot.running" >&2
      return 1
    }
}

stop_runtime() {
  local out_dir="$1"
  mkdir -p "$out_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
    >"${out_dir}/stop.intent.log" 2>&1
  wait_for_snapshot "${out_dir}/snapshot.stopped" 30 \
    "state=stopped" "mayBeActive=false" "adapterReadiness=unavailable" \
    || {
      cat "${out_dir}/snapshot.stopped" >&2
      return 1
    }
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-70-profile-lifecycle"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "s70Done" "not_claimed"

section "build_install"
if [[ "$S70_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash app/android-runtime/scripts/build-debug-apk.sh"
  (cd "$repo_root" && bash app/android-runtime/scripts/build-debug-apk.sh) \
    >"${RESULT_DIR}/build-debug-apk.log" 2>&1
  kv "build.result" "PASS"
fi
[[ -f "$APK" ]] || {
  echo "missing APK: $APK" >&2
  exit 1
}
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$(sha256sum "$APK" | awk '{print $1}')"
if [[ "$S70_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi
disable_cleanup_fault
adb_cmd shell am force-stop "$PACKAGE" >/dev/null

section "root_start"
root_state="$(start_profile root "${RESULT_DIR}/root-start")"
printf '%s\n' "$root_state" | grep -Fxq "adapterReadiness=root-nfqueue"
root_pid="$(printf '%s\n' "$root_state" | snapshot_value_from pid)"
root_generation="$(printf '%s\n' "$root_state" | snapshot_value_from generation)"
pid_alive "$root_pid"
kv "root.start" "PASS"
kv "root.pid" "$root_pid"
kv "root.generation" "$root_generation"

section "switch_root_to_vpn"
vpn_state="$(start_profile vpn "${RESULT_DIR}/switch-root-to-vpn")"
vpn_pid="$(printf '%s\n' "$vpn_state" | snapshot_value_from pid)"
vpn_generation="$(printf '%s\n' "$vpn_state" | snapshot_value_from generation)"
[[ "$vpn_pid" != "$root_pid" ]]
assert_pid_gone "$root_pid" "${RESULT_DIR}/switch-root-to-vpn/root-pid.after-switch"
adb_cmd shell ip link show tun0 >"${RESULT_DIR}/switch-root-to-vpn/tun0.running" 2>&1
kv "switch.rootToVpn" "PASS"
kv "vpn.pid" "$vpn_pid"
kv "vpn.generation" "$vpn_generation"

section "activity_recreate_does_not_stop_runtime"
adb_cmd shell input keyevent KEYCODE_HOME >/dev/null 2>&1 || true
sleep 1
adb_cmd shell am start -n "$ACTIVITY" >"${RESULT_DIR}/activity-recreate.intent.log" 2>&1
sleep 2
recreated_state="$(read_snapshot)"
printf '%s\n' "$recreated_state" >"${RESULT_DIR}/activity-recreate.snapshot"
grep -Fxq "state=running" <<<"$recreated_state"
grep -Fxq "profile=vpn" <<<"$recreated_state"
recreated_pid="$(printf '%s\n' "$recreated_state" | snapshot_value_from pid)"
recreated_generation="$(printf '%s\n' "$recreated_state" | snapshot_value_from generation)"
[[ "$recreated_pid" == "$vpn_pid" && "$recreated_generation" == "$vpn_generation" ]]
pid_alive "$vpn_pid"
kv "activity.recreateKeepsRuntime" "PASS"

section "switch_vpn_to_root"
root2_state="$(start_profile root "${RESULT_DIR}/switch-vpn-to-root")"
root2_pid="$(printf '%s\n' "$root2_state" | snapshot_value_from pid)"
root2_generation="$(printf '%s\n' "$root2_state" | snapshot_value_from generation)"
[[ "$root2_pid" != "$vpn_pid" ]]
assert_pid_gone "$vpn_pid" "${RESULT_DIR}/switch-vpn-to-root/vpn-pid.after-switch"
assert_no_tun0_residue "${RESULT_DIR}/switch-vpn-to-root/tun0.after-switch"
assert_no_connectivity_residue "${RESULT_DIR}/switch-vpn-to-root/connectivity.after-switch"
kv "switch.vpnToRoot" "PASS"
kv "root2.pid" "$root2_pid"
kv "root2.generation" "$root2_generation"

section "pause_cleanup"
paused_state="$(stop_runtime "${RESULT_DIR}/pause")"
grep -Fxq "profile=root" <<<"$paused_state"
grep -Fxq "pid=-1" <<<"$paused_state"
assert_pid_gone "$root2_pid" "${RESULT_DIR}/pause/root-pid.after-stop"
assert_no_tun0_residue "${RESULT_DIR}/pause/tun0.after-stop"
assert_no_connectivity_residue "${RESULT_DIR}/pause/connectivity.after-stop"
assert_no_native_residue "${RESULT_DIR}/pause/native-residue.after-stop"
kv "pause.result" "PASS"
kv "pause.profilePreserved" "root"

section "cleanup_fault_reason"
fault_state="$(start_profile root "${RESULT_DIR}/fault-start")"
fault_pid="$(printf '%s\n' "$fault_state" | snapshot_value_from pid)"
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeCleanupFault true \
  >"${RESULT_DIR}/cleanup-fault.enable.intent.log" 2>&1
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
  >"${RESULT_DIR}/cleanup-fault.stop.intent.log" 2>&1
wait_for_snapshot "${RESULT_DIR}/cleanup-fault.snapshot.error" 20 \
  "state=error" "errorCode=cleanup_failed" "mayBeActive=true" \
  || {
    cat "${RESULT_DIR}/cleanup-fault.snapshot.error" >&2
    exit 1
  }
disable_cleanup_fault
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
  >"${RESULT_DIR}/cleanup-fault.recover-stop.intent.log" 2>&1 || true
mkdir -p "${RESULT_DIR}/cleanup-fault"
assert_pid_gone "$fault_pid" "${RESULT_DIR}/cleanup-fault/root-pid.after-recover-stop"
kv "reason.cleanupFault" "cleanup_failed"
kv "reason.userPause" "stopped"
kv "cleanupFault.result" "PASS"

section "final_cleanup"
final_state="$(stop_runtime "${RESULT_DIR}/final-cleanup")"
grep -Fxq "state=stopped" <<<"$final_state"
assert_no_tun0_residue "${RESULT_DIR}/final-cleanup/tun0.after-stop"
assert_no_connectivity_residue "${RESULT_DIR}/final-cleanup/connectivity.after-stop"
assert_no_native_residue "${RESULT_DIR}/final-cleanup/native-residue.after-stop"
kv "finalCleanup.result" "PASS"

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s70Done" "not_claimed"
