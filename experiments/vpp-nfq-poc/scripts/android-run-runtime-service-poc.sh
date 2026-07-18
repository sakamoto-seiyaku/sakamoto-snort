#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: validate APK-native daemon packaging and the root RuntimeService HELLO gate.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-12-runtime-service-$RUN_ID"
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

stop_existing() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su "killall libsucre_snortd.so 2>/dev/null || true"
  wait_for_no_daemon || true
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
    echo "## package"
    adb_cmd shell dumpsys package "$PACKAGE" | rg 'userId=|versionName=' | tr -d '\r' || true
    echo "## battery before unplug"
    adb_cmd shell dumpsys battery | tr -d '\r'
    echo "## power before unplug"
    adb_cmd shell dumpsys power | tr -d '\r'
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

echo "# SAKAMOTO-12 Android APK-native daemon packaging and RuntimeService POC"
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

echo "building Android APK with APK-native daemon"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
capture_state after-install

echo "starting RuntimeService"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
  echo "FAIL: RuntimeService did not pass start/HELLO gate" >&2
  capture_state start-failed
  exit 1
fi

capture_state runtime-started
if ! app_read "$RUNTIME_LOG" | rg -q 'hello_artifact_abi=arm64-v8a$'; then
  echo "FAIL: artifact ABI gate missing" >&2
  failures=$((failures + 1))
fi
if ! app_read "$RUNTIME_LOG" | rg -q 'hello_daemon_build_id=.+$'; then
  echo "FAIL: daemon build ID gate missing" >&2
  failures=$((failures + 1))
fi
if ! app_read "$RUNTIME_LOG" | rg -q 'hello_capability_snort10_base=true$'; then
  echo "FAIL: snort10-base capability gate missing" >&2
  failures=$((failures + 1))
fi
root_daemon_pids="$(daemon_pids)"
if [[ -z "$root_daemon_pids" ]]; then
  echo "FAIL: no root daemon process after RuntimeService start" >&2
  failures=$((failures + 1))
else
  echo "root_daemon_pids=$root_daemon_pids"
fi

echo "stopping RuntimeService"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
if ! wait_for_no_daemon; then
  echo "FAIL: root daemon remained after RuntimeService stop" >&2
  failures=$((failures + 1))
else
  echo "runtime_stop=no_root_daemon"
fi
capture_state runtime-stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-12 RuntimeService failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-12 Android APK-native daemon packaging and RuntimeService HELLO gate"
echo "result_dir=$RESULT_DIR"
