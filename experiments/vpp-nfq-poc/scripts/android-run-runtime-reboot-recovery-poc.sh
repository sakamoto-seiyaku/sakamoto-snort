#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify RuntimeService reboot cleanup and fresh recovery.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-29-runtime-reboot-recovery-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
battery_unplugged=0

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
  while (( attempts < 20 )); do
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
  adb_cmd shell dumpsys activity services "$PACKAGE" | tr -d '\r' >"$dir/activity-services.txt" || true
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

assert_no_residue() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: $phase daemon remains" >&2; failures=$((failures + 1)); else echo "$phase=no_root_daemon"; fi
  if socket_present; then echo "FAIL: $phase socket remains" >&2; failures=$((failures + 1)); else echo "$phase=control_socket_absent"; fi
  if hooks_present; then echo "FAIL: $phase hooks remain" >&2; failures=$((failures + 1)); else echo "$phase=nfqueue_hooks_absent"; fi
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

cleanup() {
  local exit_code=$?
  stop_existing || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then exit_code=1; fi
  return "$exit_code"
}
trap cleanup EXIT

echo "# SAKAMOTO-29 RuntimeService reboot recovery POC"
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

echo "building and installing APK"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true

app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "starting RuntimeService before reboot"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "before_reboot=runtime_start_pass"; else echo "FAIL: pre-reboot start failed" >&2; failures=$((failures + 1)); fi
capture_state before-reboot
if [[ -n "$(daemon_pids)" ]]; then echo "before_reboot=root_daemon_present"; else echo "FAIL: pre-reboot daemon absent" >&2; failures=$((failures + 1)); fi

echo "rebooting device while RuntimeService is active"
reboot_device
sleep 2
adb_cmd shell dumpsys battery unplug >/dev/null 2>&1 || true
capture_state after-reboot
if wait_for_daemon_absent; then echo "after_reboot=no_root_daemon"; else echo "FAIL: daemon remains after reboot" >&2; failures=$((failures + 1)); fi
if socket_present; then echo "FAIL: socket remains after reboot" >&2; failures=$((failures + 1)); else echo "after_reboot=control_socket_absent"; fi
if hooks_present; then echo "FAIL: hooks remain after reboot" >&2; failures=$((failures + 1)); else echo "after_reboot=nfqueue_hooks_absent"; fi
if [[ -n "$(adb_cmd shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r\n')" ]]; then
  echo "after_reboot=app_process_present"
else
  echo "after_reboot=app_process_absent"
fi

echo "fresh RuntimeService recovery after reboot"
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "recovery=runtime_start_pass"; else echo "FAIL: recovery start failed" >&2; failures=$((failures + 1)); fi
capture_state recovery-running
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state recovery-stopped
assert_no_residue recovery_stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-29 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-29 RuntimeService reboot recovery"
echo "result_dir=$RESULT_DIR"
