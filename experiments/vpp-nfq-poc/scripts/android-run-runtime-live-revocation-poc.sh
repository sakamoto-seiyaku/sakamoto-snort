#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: observe KernelSU app authorization revocation without reboot.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
KSU_ALLOWLIST="/data/adb/ksu/.allowlist"
KSU_ALLOW_OFFSET="${KSU_ALLOW_OFFSET:-1824}"
KSU_ALLOWLIST_BACKUP="/data/local/tmp/sakamoto-27-allowlist-backup"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-27-runtime-live-revocation-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
battery_unplugged=0
grant_mutated=0

app_cmd() { adb_cmd shell run-as "$PACKAGE" "$@"; }
app_read() { adb_cmd shell run-as "$PACKAGE" cat "$1" 2>/dev/null | tr -d '\r'; }
daemon_pids() { adb_su 'pidof libsucre_snortd.so 2>/dev/null || true' | tr -d '\r\n'; }
socket_present() { [[ -n "$(adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true')" ]]; }
hooks_present() {
  local snapshot
  snapshot="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true')"
  [[ "$snapshot" == *"sucre-snort_"* || "$snapshot" == *"NFQUEUE"* ]]
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
  while (( attempts < 30 )); do
    if app_read "$RUNTIME_LOG" | rg -q "$pattern"; then return 0; fi
    sleep 1
    attempts=$((attempts + 1))
  done
  return 1
}

wait_for_daemon_absent() {
  local attempts=0
  while (( attempts < 15 )); do
    if [[ -z "$(daemon_pids)" ]]; then return 0; fi
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
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' \
    | tr -d '\r' >"$dir/hooks.txt"
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"$dir/control-socket.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

reboot_device() {
  adb_cmd reboot >/dev/null 2>&1 || true
  sleep 3
  for attempt in $(seq 1 60); do
    if [[ "$(adb_cmd get-state 2>/dev/null | tr -d '\r\n' || true)" == "device" ]] \
      && [[ "$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n' || true)" == "1" ]]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

set_kernel_su_allow() {
  local value="$1"
  local escaped='\000'
  [[ "$value" == "1" ]] && escaped='\001'
  adb_su "printf '$escaped' | dd of=$KSU_ALLOWLIST bs=1 seek=$KSU_ALLOW_OFFSET conv=notrunc 2>/dev/null"
  echo "root_authorization_byte=$value offset=$KSU_ALLOW_OFFSET"
}

cleanup() {
  local exit_code=$?
  stop_existing || true
  if [[ "$grant_mutated" == "1" ]]; then
    adb_su "cp $KSU_ALLOWLIST_BACKUP $KSU_ALLOWLIST" >/dev/null 2>&1 || true
    reboot_device || true
    grant_mutated=0
  fi
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then exit_code=1; fi
  return "$exit_code"
}
trap cleanup EXIT

echo "# SAKAMOTO-27 RuntimeService live KernelSU permission revocation POC"
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

echo "building and installing authorized APK"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true

adb_su "cp $KSU_ALLOWLIST $KSU_ALLOWLIST_BACKUP"
grant_mutated=1
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "authorized start before live revocation"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "before_revoke=runtime_start_pass"; else echo "FAIL: initial start failed" >&2; failures=$((failures + 1)); fi
capture_state before-revoke
if [[ -n "$(daemon_pids)" ]]; then echo "before_revoke=root_daemon_present"; else echo "FAIL: initial daemon absent" >&2; failures=$((failures + 1)); fi

echo "revoking KernelSU app authorization without reboot"
set_kernel_su_allow 0
echo "force-stopping app after live revoke"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
if wait_for_daemon_absent; then echo "after_force_stop=no_root_daemon"; else echo "FAIL: daemon survived app death after revoke" >&2; failures=$((failures + 1)); fi
sleep 2
capture_state after-force-stop
if socket_present; then echo "FAIL: after revoke socket remains" >&2; failures=$((failures + 1)); else echo "after_force_stop=control_socket_absent"; fi
if hooks_present; then echo "FAIL: after revoke hooks remain" >&2; failures=$((failures + 1)); else echo "after_force_stop=nfqueue_hooks_absent"; fi

echo "attempting new RuntimeService start without reboot"
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=(fail|pass)'; then
  if app_read "$RUNTIME_LOG" | rg -q 'runtime_start_result=fail'; then
    echo "live_revoke=effective_without_reboot"
  else
    echo "live_revoke=not_effective_without_reboot"
  fi
else
  echo "FAIL: post-revoke start produced no result" >&2
  failures=$((failures + 1))
fi
capture_state post-revoke-start
if [[ -n "$(daemon_pids)" ]]; then adb_su 'killall libsucre_snortd.so 2>/dev/null || true'; fi
clear_hooks

echo "restoring KernelSU authorization and rebooting"
adb_su "cp $KSU_ALLOWLIST_BACKUP $KSU_ALLOWLIST"
reboot_device
adb_cmd shell dumpsys battery unplug >/dev/null 2>&1 || true
grant_mutated=0
sleep 2
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "recovery=runtime_start_pass"; else echo "FAIL: recovery start failed" >&2; failures=$((failures + 1)); fi
capture_state recovery-running
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state recovery-stopped
if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: recovery daemon remains" >&2; failures=$((failures + 1)); else echo "recovery=no_root_daemon"; fi
if socket_present; then echo "FAIL: recovery socket remains" >&2; failures=$((failures + 1)); else echo "recovery=control_socket_absent"; fi
if hooks_present; then echo "FAIL: recovery hooks remain" >&2; failures=$((failures + 1)); else echo "recovery=nfqueue_hooks_absent"; fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-27 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-27 RuntimeService live KernelSU permission revocation boundary"
echo "result_dir=$RESULT_DIR"
