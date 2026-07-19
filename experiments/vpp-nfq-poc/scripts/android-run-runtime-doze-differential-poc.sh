#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: compare RuntimeService state before, during, and after a short forced Doze window.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-18081}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
DOZE_SECONDS="${DOZE_SECONDS:-10}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-19-runtime-doze-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"
APP_HTTP_LOG="files/logs/app-http-probe.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0
local_server_pid=""

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

wait_for_no_daemon() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if [[ -z "$(daemon_pids)" ]]; then return 0; fi
    sleep 1
  done
  return 1
}

wait_for_runtime_log() {
  local pattern="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if app_read "$RUNTIME_LOG" | rg -q "$pattern"; then return 0; fi
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

service_dump() {
  adb_cmd shell dumpsys activity services "$PACKAGE" | tr -d '\r'
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
  service_dump >"$dir/activity-services.txt"
  adb_cmd shell dumpsys power | tr -d '\r' >"$dir/power.txt"
  adb_cmd shell dumpsys deviceidle | tr -d '\r' >"$dir/deviceidle.txt"
  adb_cmd shell dumpsys batterystats --charged | tr -d '\r' >"$dir/batterystats.txt"
  adb_cmd shell dumpsys battery | tr -d '\r' >"$dir/battery.txt"
  adb_cmd logcat -d -s SnortRuntimeService:I SnortVpnLite:I '*:S' | tr -d '\r' \
    >"$dir/logcat.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
  app_read "$APP_HTTP_LOG" >"$dir/app-http-probe.log"
}

assert_active() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then echo "$phase=root_daemon_present"; else echo "FAIL: $phase daemon absent" >&2; failures=$((failures + 1)); fi
  if socket_present; then echo "$phase=control_socket_present"; else echo "FAIL: $phase control socket absent" >&2; failures=$((failures + 1)); fi
  if hooks_present; then echo "$phase=nfqueue_hooks_present"; else echo "FAIL: $phase NFQUEUE hooks absent" >&2; failures=$((failures + 1)); fi
  if app_read "$RUNTIME_LOG" | rg -q 'runtime_start_result=pass$'; then
    echo "$phase=runtime_start_log_pass"
  else
    echo "FAIL: $phase runtime start log missing" >&2
    failures=$((failures + 1))
  fi
}

start_local_http_probe_server() {
  adb_cmd reverse "tcp:$PORT" "tcp:$PORT" >/dev/null
  (
    printf 'HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK\r\n' \
      | nc -l -p "$PORT" -q 1 >"$RESULT_DIR/host-http-request-$1.txt"
  ) &
  local_server_pid="$!"
  sleep 1
}

stop_local_http_probe_server() {
  if [[ -n "$local_server_pid" ]]; then
    kill "$local_server_pid" >/dev/null 2>&1 || true
    wait "$local_server_pid" >/dev/null 2>&1 || true
    local_server_pid=""
  fi
  adb_cmd reverse --remove "tcp:$PORT" >/dev/null 2>&1 || true
}

probe() {
  local name="$1"
  start_local_http_probe_server "$name"
  app_cmd rm -f "$APP_HTTP_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true --es host "$HOST" --ei port "$PORT" \
    --es path "/sakamoto-19-$name" >/dev/null
  sleep 6
  local log
  log="$(app_read "$APP_HTTP_LOG")"
  printf '%s\n' "$log" >"$RESULT_DIR/$name-http.log"
  stop_local_http_probe_server
  if rg -q ' ok bytes=' <<<"$log"; then
    echo "$name=data_probe_pass"
    return 0
  fi
  echo "FAIL: $name data-plane HTTP probe failed" >&2
  failures=$((failures + 1))
  return 1
}

stop_existing() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su 'killall libsucre_snortd.so 2>/dev/null || true'
  wait_for_no_daemon || true
  clear_hooks
}

cleanup() {
  local exit_code=$?
  stop_local_http_probe_server || true
  adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
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
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then exit_code=1; fi
  return "$exit_code"
}

trap cleanup EXIT

echo "# SAKAMOTO-19 Android RuntimeService short Doze differential POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
device_preflight
stop_existing
adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-after-unplug.txt"
if ! rg -q 'USB powered: false|USB powered=false' "$RESULT_DIR/battery-after-unplug.txt"; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "building NDK daemon artifact"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
echo "building and installing Android APK"
bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
capture_identity

echo "baseline RuntimeService"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
app_cmd rm -f "$RUNTIME_LOG" "$APP_HTTP_LOG" >/dev/null 2>&1 || true
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
  echo "FAIL: baseline RuntimeService start did not pass" >&2
  exit 1
fi
capture_state baseline
assert_active baseline
probe pre-doze

echo "screen off and force Doze for ${DOZE_SECONDS}s"
adb_cmd shell input keyevent 26 >/dev/null
sleep 3
adb_cmd shell dumpsys deviceidle force-idle | tr -d '\r' | tee "$RESULT_DIR/force-idle-command.txt"
sleep "$DOZE_SECONDS"
capture_state doze
doze_dump="$(cat "$RESULT_DIR/doze/deviceidle.txt")"
if rg -q 'mState=IDLE|mState=IDLE_MAINTENANCE' <<<"$doze_dump"; then
  echo "doze=entered"
else
  echo "FAIL: device did not report forced Doze state" >&2
  failures=$((failures + 1))
fi
assert_active doze

echo "exit Doze and verify wake recovery"
adb_cmd shell dumpsys deviceidle unforce | tr -d '\r' | tee "$RESULT_DIR/unforce-command.txt"
adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
sleep 3
capture_state wake
assert_active wake
probe post-doze
capture_state wake-after-probe

echo "controlled stop"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
if wait_for_no_daemon; then echo "stop=no_root_daemon"; else echo "FAIL: controlled stop left daemon" >&2; failures=$((failures + 1)); fi
sleep 1
capture_state stopped
if socket_present; then echo "FAIL: stop control socket remains" >&2; failures=$((failures + 1)); else echo "stop=control_socket_absent"; fi
if hooks_present; then echo "FAIL: stop NFQUEUE hooks remain" >&2; failures=$((failures + 1)); else echo "stop=nfqueue_hooks_absent"; fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-19 Doze differential failures=$failures" >&2
  exit 1
fi
echo "PASS: SAKAMOTO-19 short Doze differential and wake recovery"
echo "decision=short Doze retention GO; long Doze/battery certification and foreground-service policy remain outside this POC"
echo "result_dir=$RESULT_DIR"
