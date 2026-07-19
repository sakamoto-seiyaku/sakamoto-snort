#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify RuntimeService fails closed when KernelSU denies the APK.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
MANAGER_PACKAGE="me.weishu.kernelsu"
KSU_ALLOWLIST="/data/adb/ksu/.allowlist"
KSU_ALLOW_OFFSET="${KSU_ALLOW_OFFSET:-1824}"
KSU_ALLOWLIST_BACKUP="/data/local/tmp/sakamoto-24-allowlist-backup"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-24-runtime-permission-denial-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0
grant_mutated=0

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  adb_cmd shell run-as "$PACKAGE" cat "$1" 2>/dev/null | tr -d '\r'
}

daemon_pids() {
  adb_su 'pidof libsucre_snortd.so 2>/dev/null || true' | tr -d '\r\n'
}

hook_snapshot() {
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' \
    | tr -d '\r'
}

hooks_present() {
  local snapshot
  snapshot="$(hook_snapshot)"
  [[ "$snapshot" == *"sucre-snort_"* || "$snapshot" == *"NFQUEUE"* ]]
}

socket_present() {
  [[ -n "$(adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true')" ]]
}

clear_hooks() {
  for table in iptables ip6tables; do
    adb_su "/system/bin/$table -w -D INPUT -j sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -D OUTPUT -j sucre-snort_OUTPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -F sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -F sucre-snort_OUTPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -X sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -X sucre-snort_OUTPUT" >/dev/null 2>&1 || true
  done
}

stop_existing() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su 'killall libsucre_snortd.so 2>/dev/null || true'
  clear_hooks
}

wait_for_log() {
  local pattern="$1"
  local attempts=0
  while (( attempts < 60 )); do
    if app_read "$RUNTIME_LOG" | rg -q "$pattern"; then
      return 0
    fi
    sleep 1
    attempts=$((attempts + 1))
  done
  return 1
}

capture_state() {
  local name="$1"
  local dir="$RESULT_DIR/$name"
  mkdir -p "$dir"
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' | tr -d '\r' >"$dir/processes.txt"
  hook_snapshot >"$dir/hooks.txt"
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"$dir/control-socket.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

reboot_device() {
  adb_cmd reboot >/dev/null 2>&1 || true
  sleep 3
  for attempt in $(seq 1 60); do
    local state
    state="$(adb_cmd get-state 2>/dev/null | tr -d '\r\n' || true)"
    if [[ "$state" == "device" ]]; then
      local ready
      ready="$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n' || true)"
      if [[ "$ready" == "1" ]]; then
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}

set_kernel_su_allow() {
  local value="$1"
  local escaped
  if [[ "$value" == "1" ]]; then
    escaped='\001'
  else
    escaped='\000'
  fi
  adb_su "printf '$escaped' | dd of=$KSU_ALLOWLIST bs=1 seek=$KSU_ALLOW_OFFSET conv=notrunc 2>/dev/null"
  echo "root_authorization_byte=$value offset=$KSU_ALLOW_OFFSET"
}

restore_kernel_su_grant() {
  echo "restoring KernelSU grant through allowlist profile"
  set_kernel_su_allow 1
  reboot_device
  adb_cmd shell dumpsys battery unplug >/dev/null 2>&1 || true
  grant_mutated=0
  echo "root_authorization=restored"
}

cleanup() {
  local exit_code=$?
  stop_existing || true
  if [[ "$grant_mutated" == "1" ]]; then
    set_kernel_su_allow 1 || true
    reboot_device || true
    grant_mutated=0
  fi
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then
    exit_code=1
  fi
  return "$exit_code"
}

trap cleanup EXIT

echo "# SAKAMOTO-24 RuntimeService root permission denial POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"

device_preflight
stop_existing
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
if ! adb_cmd shell dumpsys battery | tr -d '\r' | rg -q 'USB powered: false|USB powered=false'; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "building NDK daemon artifact"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
echo "building and installing Android APK"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
adb_su "cp $KSU_ALLOWLIST $KSU_ALLOWLIST_BACKUP"
set_kernel_su_allow 0
grant_mutated=1
echo "denying KernelSU authorization and rebooting"
reboot_device
adb_cmd shell dumpsys battery unplug >/dev/null 2>&1 || true
{
  echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
  echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
  echo "abi=$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
  echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
  echo "daemon_artifact_sha256=$(sha256sum "$REPO_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so")"
} >"$RESULT_DIR/device-identity.txt"

app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "denied root start"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=fail'; then
  echo "denied=runtime_start_failure_logged"
else
  echo "FAIL: denied root start did not log explicit failure" >&2
  failures=$((failures + 1))
fi
capture_state denied
if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: denied start left root daemon" >&2; failures=$((failures + 1)); else echo "denied=no_root_daemon"; fi
if socket_present; then echo "FAIL: denied start left control socket" >&2; failures=$((failures + 1)); else echo "denied=control_socket_absent"; fi
if hooks_present; then echo "FAIL: denied start left NFQUEUE hooks" >&2; failures=$((failures + 1)); else echo "denied=nfqueue_hooks_absent"; fi

restore_kernel_su_grant
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "authorized recovery"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "recovery=runtime_start_pass"; else echo "FAIL: authorized recovery did not start" >&2; failures=$((failures + 1)); fi
capture_state recovery-started
if [[ -n "$(daemon_pids)" ]]; then echo "recovery=root_daemon_present"; else echo "FAIL: recovery daemon absent" >&2; failures=$((failures + 1)); fi
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state recovery-stopped
if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: recovery stop left root daemon" >&2; failures=$((failures + 1)); else echo "recovery=no_root_daemon"; fi
if socket_present; then echo "FAIL: recovery stop left control socket" >&2; failures=$((failures + 1)); else echo "recovery=control_socket_absent"; fi
if hooks_present; then echo "FAIL: recovery stop left NFQUEUE hooks" >&2; failures=$((failures + 1)); else echo "recovery=nfqueue_hooks_absent"; fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-24 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-24 RuntimeService root permission denial boundary"
echo "result_dir=$RESULT_DIR"
