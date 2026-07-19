#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: measure graceful and SIGKILL daemon cleanup on Android.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-17-daemon-signal-boundary-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null | tr -d '\r' || true
}

ps_snapshot() {
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r'
}

daemon_pids() {
  ps_snapshot | awk '($1 == "0" || $1 == "root") && ($5 == "libsucre_snortd.so" || index($6, "libsucre_snortd.so") > 0) { print $2 }'
}

daemon_pid() {
  daemon_pids | head -n 1
}

wait_for_runtime_log() {
  local pattern="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if app_read "$RUNTIME_LOG" | rg -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_no_daemon() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if [[ -z "$(daemon_pids)" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
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

capture_identity() {
  {
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(resolve_adb_serial)"
    echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
    echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    echo "build_fingerprint=$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "abi=$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
    echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
    echo "daemon_artifact_sha256=$(sha256sum "$REPO_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so")"
    adb_cmd shell dumpsys package "$PACKAGE" | rg 'userId=|versionName=' | tr -d '\r' || true
  } >"$RESULT_DIR/device-identity.txt"
}

capture_state() {
  local name="$1"
  local dir="$RESULT_DIR/$name"
  mkdir -p "$dir"
  ps_snapshot >"$dir/processes.txt"
  hook_snapshot >"$dir/hooks.txt"
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"$dir/control-socket.txt"
  adb_cmd logcat -d -s SnortRuntimeService:I SnortVpnLite:I '*:S' | tr -d '\r' \
    >"$dir/logcat.txt"
  adb_cmd shell dumpsys battery | tr -d '\r' >"$dir/battery.txt"
  adb_cmd shell dumpsys power | tr -d '\r' >"$dir/power.txt"
  adb_cmd shell dumpsys deviceidle | tr -d '\r' >"$dir/deviceidle.txt"
  app_cmd ls -la files/lib files/logs 2>/dev/null | tr -d '\r' >"$dir/app-files.txt" || true
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

stop_existing() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su 'killall libsucre_snortd.so 2>/dev/null || true'
  wait_for_no_daemon || true
  clear_hooks
}

cleanup() {
  local exit_code=$?
  stop_existing || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  ps_snapshot >"$RESULT_DIR/processes-after-cleanup.txt" || true
  hook_snapshot >"$RESULT_DIR/hooks-after-cleanup.txt" || true
  adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-after-reset.txt" || true
  if [[ -n "$(daemon_pids)" ]]; then
    echo "cleanup FAIL: root daemon remains" >&2
    failures=$((failures + 1))
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then
    exit_code=1
  fi
  return "$exit_code"
}

trap cleanup EXIT

assert_no_residue() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then
    echo "FAIL: $phase daemon remains" >&2
    failures=$((failures + 1))
  else
    echo "$phase=no_root_daemon"
  fi
  if socket_present; then
    echo "FAIL: $phase control socket remains" >&2
    failures=$((failures + 1))
  else
    echo "$phase=control_socket_absent"
  fi
}

start_runtime() {
  local phase="$1"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
  app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
  if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
    echo "FAIL: $phase RuntimeService start failed" >&2
    failures=$((failures + 1))
    return 1
  fi
  echo "$phase=runtime_start_pass"
}

stop_runtime() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
  if wait_for_no_daemon; then
    echo "$1=no_root_daemon"
  else
    echo "FAIL: $1 stop left daemon" >&2
    failures=$((failures + 1))
  fi
  sleep 1
}

echo "# SAKAMOTO-17 Android daemon signal cleanup boundary POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"

device_preflight
stop_existing
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
battery_after_unplug="$(adb_cmd shell dumpsys battery | tr -d '\r')"
printf '%s\n' "$battery_after_unplug" >"$RESULT_DIR/battery-after-unplug.txt"
if ! grep -Eq 'USB powered: false|USB powered=false' <<<"$battery_after_unplug"; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "building NDK daemon artifact"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
echo "building and installing Android APK"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
capture_identity

echo "graceful SIGTERM boundary"
start_runtime sigterm
capture_state sigterm-started
if hooks_present; then echo "sigterm_start=nfqueue_hooks_present"; else failures=$((failures + 1)); echo "FAIL: SIGTERM hooks absent" >&2; fi
sigterm_pid="$(daemon_pid)"
if [[ -z "$sigterm_pid" ]]; then
  echo "FAIL: SIGTERM daemon PID missing" >&2
  failures=$((failures + 1))
else
  echo "sigterm_pid=$sigterm_pid"
  adb_su "kill -TERM $sigterm_pid"
fi
if wait_for_no_daemon; then echo "sigterm=no_root_daemon"; else echo "FAIL: SIGTERM daemon remains" >&2; failures=$((failures + 1)); fi
capture_state sigterm-after
if hooks_present; then echo "FAIL: SIGTERM hooks remain" >&2; failures=$((failures + 1)); else echo "sigterm=nfqueue_hooks_absent"; fi
assert_no_residue sigterm
if app_read "$RUNTIME_LOG" | rg -q 'hook cleanup=pass$'; then echo "sigterm=daemon_hook_cleanup_pass"; else echo "FAIL: SIGTERM cleanup log missing" >&2; failures=$((failures + 1)); fi

echo "SIGTERM recovery"
start_runtime sigterm-recovery
capture_state sigterm-recovered-started
stop_runtime sigterm-recovery-stop
capture_state sigterm-recovered-stopped
if hooks_present; then echo "FAIL: SIGTERM recovery hooks remain" >&2; failures=$((failures + 1)); else echo "sigterm_recovery=nfqueue_hooks_absent"; fi

echo "uncatchable SIGKILL boundary"
start_runtime sigkill
capture_state sigkill-started
if hooks_present; then echo "sigkill_start=nfqueue_hooks_present"; else failures=$((failures + 1)); echo "FAIL: SIGKILL hooks absent" >&2; fi
sigkill_pid="$(daemon_pid)"
if [[ -z "$sigkill_pid" ]]; then
  echo "FAIL: SIGKILL daemon PID missing" >&2
  failures=$((failures + 1))
else
  echo "sigkill_pid=$sigkill_pid"
  adb_su "kill -KILL $sigkill_pid"
fi
if wait_for_no_daemon; then echo "sigkill=no_root_daemon"; else echo "FAIL: SIGKILL daemon remains" >&2; failures=$((failures + 1)); fi
capture_state sigkill-before-manual-cleanup
assert_no_residue sigkill-before-manual-cleanup
if hooks_present; then echo "sigkill=hooks_remain_before_manual_cleanup"; else echo "sigkill=hooks_absent_before_manual_cleanup"; fi
if app_read "$RUNTIME_LOG" | rg -q 'hook cleanup=pass$'; then echo "sigkill=unexpected_cleanup_log"; else echo "sigkill=no_destructor_cleanup_log"; fi

echo "manual cleanup after SIGKILL evidence"
clear_hooks
adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
capture_state sigkill-after-manual-cleanup
if hooks_present; then echo "FAIL: manual SIGKILL cleanup left hooks" >&2; failures=$((failures + 1)); else echo "sigkill=manual_cleanup_complete"; fi

echo "SIGKILL recovery"
start_runtime sigkill-recovery
capture_state sigkill-recovered-started
if hooks_present; then echo "sigkill_recovery=nfqueue_hooks_present"; else echo "FAIL: SIGKILL recovery hooks absent" >&2; failures=$((failures + 1)); fi
stop_runtime sigkill-recovery-stop
capture_state sigkill-recovered-stopped
if hooks_present; then echo "FAIL: SIGKILL recovery hooks remain" >&2; failures=$((failures + 1)); else echo "sigkill_recovery=nfqueue_hooks_absent"; fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-17 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-17 daemon signal cleanup boundary"
echo "result_dir=$RESULT_DIR"
