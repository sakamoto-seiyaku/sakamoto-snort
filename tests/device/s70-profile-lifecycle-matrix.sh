#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-70 product RuntimeService profile lifecycle evidence matrix.
#
# Covers the product DebugControlActivity/RuntimeService path for clean
# Root↔VPN profile switch, user pause cleanup, Activity recreation survival,
# bounded cleanup-fault reason, runtime crash/restart, short Doze baseline,
# and reboot baseline inventory. A forced reboot is not run by default.

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
S70_DOZE_FORCE_IDLE="${S70_DOZE_FORCE_IDLE:-1}"
S70_RUN_REBOOT="${S70_RUN_REBOOT:-0}"
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

section "runtime_crash_restart"
crash_state="$(start_profile root "${RESULT_DIR}/crash-start")"
crash_pid="$(printf '%s\n' "$crash_state" | snapshot_value_from pid)"
adb_cmd shell su 0 sh -c "kill -KILL $crash_pid" \
  >"${RESULT_DIR}/runtime-crash.kill.log" 2>&1
crash_recovered=0
crash_mode=""
crash_recovered_pid=""
mkdir -p "${RESULT_DIR}/runtime-crash"
for _ in $(seq 1 30); do
  state="$(read_snapshot)"
  process_alive=0
  if pid_alive "$crash_pid"; then
    process_alive=1
  fi
  {
    echo "crashedPid=$crash_pid"
    echo "processAlive=$process_alive"
    printf '%s\n' "$state"
  } >"${RESULT_DIR}/runtime-crash/snapshot"
  if [[ "$process_alive" == "0" ]]; then
    if grep -Fxq "state=stopped" <<<"$state" \
        && grep -Fxq "errorCode=unexpected_exit" <<<"$state" \
        && grep -Fxq "mayBeActive=false" <<<"$state"; then
      crash_recovered=1
      crash_mode="durable-unexpected-exit"
      break
    fi
    if grep -Fxq "state=running" <<<"$state" \
        && grep -Fxq "profile=root" <<<"$state" \
        && grep -Fxq "health=ok" <<<"$state" \
        && grep -Fxq "coreHealth=ok" <<<"$state"; then
      candidate_pid="$(printf '%s\n' "$state" | snapshot_value_from pid)"
      if [[ "$candidate_pid" =~ ^[0-9]+$ && "$candidate_pid" != "$crash_pid" ]]; then
        crash_recovered=1
        crash_mode="automatic-new-owner"
        crash_recovered_pid="$candidate_pid"
        break
      fi
    fi
  fi
  sleep 1
done
if [[ "$crash_recovered" != "1" ]]; then
  kv "crash.result" "FAIL"
  cat "${RESULT_DIR}/runtime-crash/snapshot" >&2
  exit 1
fi
printf 'crashRecoveryMode=%s\ncrashRecoveredPid=%s\n' \
  "$crash_mode" "$crash_recovered_pid" >>"${RESULT_DIR}/runtime-crash/snapshot"
if [[ "$crash_mode" == "automatic-new-owner" ]]; then
  stop_runtime "${RESULT_DIR}/runtime-crash/auto-owner-stop" >/dev/null
fi
assert_no_native_residue "${RESULT_DIR}/runtime-crash/native-residue.after-recovery"
restart_state="$(start_profile root "${RESULT_DIR}/restart-after-crash")"
restart_pid="$(printf '%s\n' "$restart_state" | snapshot_value_from pid)"
pid_alive "$restart_pid"
stop_runtime "${RESULT_DIR}/restart-after-crash-stop" >/dev/null
assert_pid_gone "$restart_pid" "${RESULT_DIR}/restart-after-crash/root-pid.after-stop"
assert_no_native_residue "${RESULT_DIR}/restart-after-crash/native-residue.after-stop"
kv "crash.mode" "$crash_mode"
kv "crash.result" "PASS"
kv "restartAfterCrash.result" "PASS"

section "doze_baseline"
mkdir -p "${RESULT_DIR}/doze"
doze_state="$(start_profile root "${RESULT_DIR}/doze-start")"
doze_pid="$(printf '%s\n' "$doze_state" | snapshot_value_from pid)"
adb_cmd shell dumpsys deviceidle >"${RESULT_DIR}/doze.before" 2>&1 || true
kv "doze.forceIdleRequested" "$S70_DOZE_FORCE_IDLE"
if [[ "$S70_DOZE_FORCE_IDLE" == "1" ]]; then
  set +e
  adb_cmd shell cmd deviceidle force-idle >"${RESULT_DIR}/doze.force-idle.log" 2>&1
  doze_force_rc=$?
  set -e
  kv "doze.forceIdleRc" "$doze_force_rc"
  sleep 3
  adb_cmd shell dumpsys deviceidle >"${RESULT_DIR}/doze.during" 2>&1 || true
  adb_cmd shell cmd deviceidle unforce >"${RESULT_DIR}/doze.unforce.log" 2>&1 || true
  adb_cmd shell dumpsys deviceidle >"${RESULT_DIR}/doze.after" 2>&1 || true
  if [[ "$doze_force_rc" == "0" ]]; then
    after_doze_state="$(read_snapshot)"
    printf '%s\n' "$after_doze_state" >"${RESULT_DIR}/doze.snapshot.after"
    grep -Fxq "state=running" <<<"$after_doze_state"
    grep -Fxq "profile=root" <<<"$after_doze_state"
    [[ "$(printf '%s\n' "$after_doze_state" | snapshot_value_from pid)" == "$doze_pid" ]]
    pid_alive "$doze_pid"
    kv "doze.result" "PASS"
  else
    kv "doze.result" "UNAVAILABLE"
  fi
else
  kv "doze.result" "SKIPPED"
fi
stop_runtime "${RESULT_DIR}/doze-stop" >/dev/null
assert_no_native_residue "${RESULT_DIR}/doze/native-residue.after-stop"

section "reboot_baseline"
adb_cmd shell getprop sys.boot_completed >"${RESULT_DIR}/reboot.sys_boot_completed" 2>&1 || true
adb_cmd shell getprop ro.boot.bootreason >"${RESULT_DIR}/reboot.bootreason" 2>&1 || true
adb_cmd shell cat /proc/uptime >"${RESULT_DIR}/reboot.uptime" 2>&1 || true
kv "reboot.defaultForced" "$S70_RUN_REBOOT"
if [[ "$S70_RUN_REBOOT" == "1" ]]; then
  mkdir -p "${RESULT_DIR}/reboot"
  reboot_state="$(start_profile root "${RESULT_DIR}/reboot-start")"
  reboot_pid="$(printf '%s\n' "$reboot_state" | snapshot_value_from pid)"
  kv "reboot.prePid" "$reboot_pid"
  adb_cmd reboot >"${RESULT_DIR}/reboot.command.log" 2>&1 || true
  sleep 5
  adb_cmd wait-for-device >"${RESULT_DIR}/reboot.wait-for-device.log" 2>&1
  boot_completed=0
  for _ in $(seq 1 90); do
    if [[ "$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n')" == "1" ]]; then
      boot_completed=1
      break
    fi
    sleep 2
  done
  [[ "$boot_completed" == "1" ]] || {
    kv "reboot.result" "FAIL_BOOT_TIMEOUT"
    exit 1
  }
  adb_cmd shell getprop sys.boot_completed >"${RESULT_DIR}/reboot.after.sys_boot_completed" 2>&1 || true
  adb_cmd shell getprop ro.boot.bootreason >"${RESULT_DIR}/reboot.after.bootreason" 2>&1 || true
  adb_cmd shell cat /proc/uptime >"${RESULT_DIR}/reboot.after.uptime" 2>&1 || true
  assert_no_native_residue "${RESULT_DIR}/reboot/native-residue.after-boot"
  adb_cmd shell am start -n "$ACTIVITY" >"${RESULT_DIR}/reboot.query.intent.log" 2>&1
  recovered_inactive=0
  for _ in $(seq 1 45); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"${RESULT_DIR}/reboot/snapshot.after-query"
    if grep -Fxq "mayBeActive=false" <<<"$state" \
        && grep -Fxq "pid=-1" <<<"$state"; then
      recovered_inactive=1
      break
    fi
    sleep 1
  done
  [[ "$recovered_inactive" == "1" ]] || {
    kv "reboot.result" "FAIL_RECOVERY"
    cat "${RESULT_DIR}/reboot/snapshot.after-query" >&2
    exit 1
  }
  reboot_restart_state="$(start_profile root "${RESULT_DIR}/reboot-manual-restart")"
  reboot_restart_pid="$(printf '%s\n' "$reboot_restart_state" | snapshot_value_from pid)"
  pid_alive "$reboot_restart_pid"
  stop_runtime "${RESULT_DIR}/reboot-manual-restart-stop" >/dev/null
  assert_pid_gone "$reboot_restart_pid" "${RESULT_DIR}/reboot/root-pid.after-manual-stop"
  assert_no_native_residue "${RESULT_DIR}/reboot/native-residue.after-manual-stop"
  kv "reboot.bootCompleted" "PASS"
  kv "reboot.recoveredInactive" "PASS"
  kv "reboot.manualRestart" "PASS"
  kv "reboot.result" "PASS"
else
  kv "reboot.result" "BASELINE_RECORDED"
fi

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
