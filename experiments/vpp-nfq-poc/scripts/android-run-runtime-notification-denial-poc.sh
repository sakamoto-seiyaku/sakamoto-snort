#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: observe RuntimeService behavior when POST_NOTIFICATIONS is denied.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-31-runtime-notification-denial-$RUN_ID"
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
  adb_cmd shell dumpsys notification --noredact | tr -d '\r' \
    | rg -n -C 2 "$PACKAGE|Snort runtime|snort-runtime" >"$dir/notification-matches.txt" || true
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

assert_no_residue() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: $phase daemon remains" >&2; failures=$((failures + 1)); else echo "$phase=no_root_daemon"; fi
  if socket_present; then echo "FAIL: $phase socket remains" >&2; failures=$((failures + 1)); else echo "$phase=control_socket_absent"; fi
  if hooks_present; then echo "FAIL: $phase hooks remain" >&2; failures=$((failures + 1)); else echo "$phase=nfqueue_hooks_absent"; fi
}

cleanup() {
  local exit_code=$?
  stop_existing || true
  adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then exit_code=1; fi
  return "$exit_code"
}
trap cleanup EXIT

echo "# SAKAMOTO-31 RuntimeService notification permission denial POC"
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
adb_cmd shell pm revoke "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
echo "notification_permission=$(adb_cmd shell dumpsys package "$PACKAGE" | rg 'POST_NOTIFICATIONS' | tr -d '\r' || true)"

app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "starting RuntimeService with notification permission denied"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'foreground_service_start=(pass|fail)'; then
  if app_read "$RUNTIME_LOG" | rg -q 'foreground_service_start=pass'; then echo "denied=foreground_service_start_pass"; else echo "denied=foreground_service_start_fail"; fi
else
  echo "FAIL: foreground service result missing" >&2
  failures=$((failures + 1))
fi
if wait_for_log 'runtime_start_result=(pass|fail)'; then
  if app_read "$RUNTIME_LOG" | rg -q 'runtime_start_result=pass'; then echo "denied=runtime_start_pass"; else echo "denied=runtime_start_fail"; fi
else
  echo "FAIL: denied runtime result missing" >&2
  failures=$((failures + 1))
fi
capture_state denied-running
if [[ -n "$(daemon_pids)" ]]; then echo "denied=root_daemon_present"; else echo "denied=no_root_daemon"; fi
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state denied-stopped
assert_no_residue denied_stopped

echo "restoring notification permission and recovering"
adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS
adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
sleep 2
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if wait_for_log 'runtime_start_result=pass$'; then echo "recovery=runtime_start_pass"; else echo "FAIL: permission recovery start failed" >&2; failures=$((failures + 1)); fi
capture_state recovery-running
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state recovery-stopped
assert_no_residue recovery_stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-31 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-31 RuntimeService notification permission denial boundary"
echo "result_dir=$RESULT_DIR"
