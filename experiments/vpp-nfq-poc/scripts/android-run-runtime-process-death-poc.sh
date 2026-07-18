#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: observe RuntimeService process-death and root-daemon orphan behavior.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-13-runtime-process-death-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0
orphaned=0

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null | tr -d '\r' || true
}

ps_snapshot() {
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r'
}

app_pids() {
  ps_snapshot | awk -v package="$PACKAGE" '($5 == package || index($6, package) > 0) { print $2 }'
}

daemon_pids() {
  ps_snapshot | awk '($1 == "0" || $1 == "root") && ($5 == "libsucre_snortd.so" || index($6, "libsucre_snortd.so") > 0) { print $2 }'
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
  adb_su "killall libsucre_snortd.so 2>/dev/null || true"
  wait_for_no_daemon || true
}

cleanup() {
  stop_existing || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  ps_snapshot >"$RESULT_DIR/processes-after-cleanup.txt" || true
  adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-after-reset.txt" || true
  if [[ -n "$(daemon_pids)" ]]; then
    echo "cleanup FAIL: root daemon remains" >&2
    daemon_pids >&2 || true
    failures=$((failures + 1))
  fi
}
trap cleanup EXIT INT TERM

echo "# SAKAMOTO-13 Android RuntimeService process-death POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
capture_identity

device_preflight
stop_existing
app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
battery_after_unplug="$(adb_cmd shell dumpsys battery | tr -d '\r')"
printf '%s\n' "$battery_after_unplug" >"$RESULT_DIR/battery-after-unplug.txt"
if ! grep -Eq 'USB powered: false|USB powered=false' <<<"$battery_after_unplug"; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "building Android APK"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
capture_state after-install

echo "starting RuntimeService baseline"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
  echo "FAIL: baseline RuntimeService start failed" >&2
  capture_state start-failed
  exit 1
fi
capture_state baseline-started
baseline_daemon_pid="$(daemon_pids | head -n 1)"
if [[ -z "$baseline_daemon_pid" ]]; then
  echo "FAIL: baseline root daemon missing" >&2
  failures=$((failures + 1))
else
  echo "baseline_root_daemon_pid=$baseline_daemon_pid"
fi

echo "force-stopping APK process"
adb_cmd shell am force-stop "$PACKAGE"
sleep 3
capture_state after-force-stop
if [[ -n "$(app_pids)" ]]; then
  echo "FAIL: APK process remained after force-stop" >&2
  app_pids >&2 || true
  failures=$((failures + 1))
else
  echo "after_force_stop=app_absent"
fi
orphaned_daemon_pid="$(daemon_pids | head -n 1)"
if [[ -n "$orphaned_daemon_pid" ]]; then
  orphaned=1
  echo "after_force_stop=root_daemon_orphaned pid=$orphaned_daemon_pid"
else
  echo "after_force_stop=no_root_daemon"
fi

echo "performing explicit root cleanup"
adb_su "killall libsucre_snortd.so 2>/dev/null || true"
if ! wait_for_no_daemon; then
  echo "FAIL: explicit root cleanup did not remove daemon" >&2
  failures=$((failures + 1))
else
  echo "explicit_cleanup=no_root_daemon"
fi

app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
echo "restarting RuntimeService after explicit cleanup"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
  echo "FAIL: RuntimeService did not recover after explicit cleanup" >&2
  capture_state recovery-failed
  exit 1
fi
capture_state recovery-started
recovery_daemon_pid="$(daemon_pids | head -n 1)"
if [[ -z "$recovery_daemon_pid" ]]; then
  echo "FAIL: recovery root daemon missing" >&2
  failures=$((failures + 1))
else
  echo "recovery_root_daemon_pid=$recovery_daemon_pid"
fi

echo "stopping recovered RuntimeService"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
if ! wait_for_no_daemon; then
  echo "FAIL: recovered RuntimeService stop left daemon" >&2
  failures=$((failures + 1))
else
  echo "recovered_runtime_stop=no_root_daemon"
fi
capture_state final-stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-13 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
if [[ "$orphaned" == "1" ]]; then
  echo "PASS: SAKAMOTO-13 observed root daemon orphan after app force-stop"
  echo "decision=HOLD automatic recovery; explicit root cleanup required"
else
  echo "PASS: SAKAMOTO-13 app force-stop did not orphan root daemon"
  echo "decision=GO observed cleanup boundary; automatic restart remains separate"
fi
echo "result_dir=$RESULT_DIR"
