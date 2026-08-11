#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-54 current Android RuntimeService upgrade/rollback device gate.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s54-upgrade-rollback-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
STATE_PATH="files/runtime-state/snapshot.properties"
OLD_APK="${RESULT_DIR}/sakamoto-runtime-old.apk"
NEW_APK="${RESULT_DIR}/sakamoto-runtime-new.apk"

mkdir -p "$RESULT_DIR"

kv() { printf '%s=%s\n' "$1" "$2"; }
section() { printf '\n## %s\n' "$1"; }

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

daemon_pids() {
  adb_su 'pidof libsucre_snortd.so 2>/dev/null || true' | tr -d '\r\n'
}

pid_alive() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || return 1
  adb_su "kill -0 $pid" >/dev/null 2>&1
}

assert_no_native_residue() {
  local out_dir="$1"
  mkdir -p "$out_dir"
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' \
    | tr -d '\r' >"${out_dir}/processes.txt" || true
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' \
    | tr -d '\r' >"${out_dir}/hooks.txt" || true
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"${out_dir}/control-socket.txt" || true
  ! grep -Fq 'libsucre_snortd.so' "${out_dir}/processes.txt"
  ! grep -Eq 'sucre-snort_|NFQUEUE' "${out_dir}/hooks.txt"
  [[ ! -s "${out_dir}/control-socket.txt" ]]
}

start_root() {
  local out_dir="$1"
  mkdir -p "$out_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile root \
    >"${out_dir}/start.intent.log" 2>&1
  local state pid
  for _ in $(seq 1 45); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"${out_dir}/snapshot.running"
    if grep -Fxq "state=running" <<<"$state" \
        && grep -Fxq "profile=root" <<<"$state" \
        && grep -Fxq "health=ok" <<<"$state" \
        && grep -Fxq "coreHealth=ok" <<<"$state"; then
      pid="$(printf '%s\n' "$state" | snapshot_value_from pid || true)"
      if pid_alive "$pid"; then
        printf '%s\n' "$state"
        return 0
      fi
    fi
    sleep 1
  done
  cat "${out_dir}/snapshot.running" >&2
  return 1
}

stop_runtime() {
  local out_dir="$1"
  mkdir -p "$out_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
    >"${out_dir}/stop.intent.log" 2>&1 || true
  wait_for_snapshot "${out_dir}/snapshot.stopped" 30 \
    "state=stopped" "mayBeActive=false" "adapterReadiness=unavailable" || true
}

build_versioned_apk() {
  local code="$1"
  local name="$2"
  local target="$3"
  (cd "$repo_root" && APK_VERSION_CODE="$code" APK_VERSION_NAME="$name" \
    bash app/android-runtime/scripts/build-debug-apk.sh) \
    >"${RESULT_DIR}/build-${name}.log" 2>&1
  cp "$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk" "$target"
}

cleanup() {
  stop_runtime "${RESULT_DIR}/cleanup-stop" >/dev/null 2>&1 || true
  assert_no_native_residue "${RESULT_DIR}/cleanup-native-residue" >/dev/null 2>&1 || true
}
trap cleanup EXIT

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-54-upgrade-rollback"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"

section "build"
build_versioned_apk 1 "0.1-s54-old" "$OLD_APK"
build_versioned_apk 2 "0.2-s54-new" "$NEW_APK"
kv "old.apk.sha256" "$(sha256sum "$OLD_APK" | awk '{ print $1 }')"
kv "new.apk.sha256" "$(sha256sum "$NEW_APK" | awk '{ print $1 }')"

section "install_old_start"
adb_cmd install -r -d "$OLD_APK" >"${RESULT_DIR}/install-old.log" 2>&1
adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
old_state="$(start_root "${RESULT_DIR}/old-start")"
old_pid="$(printf '%s\n' "$old_state" | snapshot_value_from pid)"
kv "old.pid" "$old_pid"

section "upgrade_active"
adb_cmd install -r "$NEW_APK" >"${RESULT_DIR}/install-new.log" 2>&1
for _ in $(seq 1 30); do
  if [[ -z "$(daemon_pids)" ]]; then
    break
  fi
  sleep 1
done
assert_no_native_residue "${RESULT_DIR}/after-upgrade-native-residue"
kv "upgrade.noResidue" "PASS"
new_state="$(start_root "${RESULT_DIR}/new-start")"
new_pid="$(printf '%s\n' "$new_state" | snapshot_value_from pid)"
kv "new.pid" "$new_pid"
stop_runtime "${RESULT_DIR}/new-stop" >/dev/null
assert_no_native_residue "${RESULT_DIR}/after-new-stop-native-residue"

section "rollback_active"
new_active_state="$(start_root "${RESULT_DIR}/new-active-before-rollback")"
new_active_pid="$(printf '%s\n' "$new_active_state" | snapshot_value_from pid)"
kv "newActive.pid" "$new_active_pid"
adb_cmd install -r -d "$OLD_APK" >"${RESULT_DIR}/install-old-rollback.log" 2>&1
for _ in $(seq 1 30); do
  if [[ -z "$(daemon_pids)" ]]; then
    break
  fi
  sleep 1
done
assert_no_native_residue "${RESULT_DIR}/after-rollback-native-residue"
kv "rollback.noResidue" "PASS"
old_after_state="$(start_root "${RESULT_DIR}/old-start-after-rollback")"
old_after_pid="$(printf '%s\n' "$old_after_state" | snapshot_value_from pid)"
kv "oldAfterRollback.pid" "$old_after_pid"
stop_runtime "${RESULT_DIR}/old-stop-after-rollback" >/dev/null
assert_no_native_residue "${RESULT_DIR}/final-native-residue"

section "matrix_result"
kv "upgrade.result" "PASS"
kv "rollback.result" "PASS"
kv "matrix.result" "PASS"
