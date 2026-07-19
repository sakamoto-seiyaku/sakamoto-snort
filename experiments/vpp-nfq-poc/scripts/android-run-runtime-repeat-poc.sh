#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: validate bounded Android RuntimeService lifecycle repeatability.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
CYCLES="${CYCLES:-5}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-16-runtime-repeat-$RUN_ID"
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

wait_for_hooks_present() {
  local deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    if hooks_present; then
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

top_level_jump_count() {
  hook_snapshot | awk '$1 == "-A" && ($2 == "INPUT" || $2 == "OUTPUT") && ($4 == "sucre-snort_INPUT" || $4 == "sucre-snort_OUTPUT") { count++ } END { print count + 0 }'
}

socket_present() {
  [[ -n "$(adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true')" ]]
}

clear_hooks() {
  adb_su 'for table in iptables ip6tables; do
    /system/bin/$table -w -D INPUT -j sucre-snort_INPUT 2>/dev/null || true
    /system/bin/$table -w -D OUTPUT -j sucre-snort_OUTPUT 2>/dev/null || true
    /system/bin/$table -w -F sucre-snort_INPUT 2>/dev/null || true
    /system/bin/$table -w -F sucre-snort_OUTPUT 2>/dev/null || true
    /system/bin/$table -w -X sucre-snort_INPUT 2>/dev/null || true
    /system/bin/$table -w -X sucre-snort_OUTPUT 2>/dev/null || true
  done' >/dev/null 2>&1 || true
}

seed_preexisting_hooks() {
  : >"$RESULT_DIR/preexisting-seed-command.txt"
  for table in iptables ip6tables; do
    adb_su "/system/bin/$table -w -N sucre-snort_INPUT" \
      >>"$RESULT_DIR/preexisting-seed-command.txt" 2>&1 || true
    adb_su "/system/bin/$table -w -N sucre-snort_OUTPUT" \
      >>"$RESULT_DIR/preexisting-seed-command.txt" 2>&1 || true
    adb_su "/system/bin/$table -w -A INPUT -j sucre-snort_INPUT" \
      >>"$RESULT_DIR/preexisting-seed-command.txt" 2>&1 || true
    adb_su "/system/bin/$table -w -A OUTPUT -j sucre-snort_OUTPUT" \
      >>"$RESULT_DIR/preexisting-seed-command.txt" 2>&1 || true
  done
}

capture_identity() {
  {
    echo "run_id=$RUN_ID"
    echo "cycles=$CYCLES"
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

assert_hooks_present() {
  local phase="$1"
  if hooks_present; then
    echo "$phase=nfqueue_hooks_present"
  else
    echo "FAIL: $phase NFQUEUE hooks absent" >&2
    failures=$((failures + 1))
  fi
}

assert_hooks_absent() {
  local phase="$1"
  if hooks_present; then
    echo "FAIL: $phase NFQUEUE hooks remain" >&2
    failures=$((failures + 1))
  else
    echo "$phase=nfqueue_hooks_absent"
  fi
}

assert_single_family_jumps() {
  local phase="$1"
  local count
  count="$(top_level_jump_count)"
  if [[ "$count" == "4" ]]; then
    echo "$phase=top_level_jump_count_4"
  else
    echo "FAIL: $phase expected 4 top-level jumps, got $count" >&2
    failures=$((failures + 1))
  fi
}

assert_cleanup_log() {
  local phase="$1"
  if app_read "$RUNTIME_LOG" | rg -q 'hook cleanup=pass$'; then
    echo "$phase=daemon_hook_cleanup_pass"
  else
    echo "FAIL: $phase cleanup log missing" >&2
    failures=$((failures + 1))
  fi
}

start_runtime() {
  app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
  if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
    echo "FAIL: RuntimeService start failed" >&2
    failures=$((failures + 1))
    return 1
  fi
  if ! wait_for_hooks_present; then
    echo "FAIL: RuntimeService start did not expose NFQUEUE hooks" >&2
    failures=$((failures + 1))
    return 1
  fi
  return 0
}

stop_runtime() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
  if wait_for_no_daemon; then
    echo "stop=no_root_daemon"
  else
    echo "FAIL: RuntimeService stop left daemon" >&2
    failures=$((failures + 1))
  fi
  assert_hooks_absent stop
  if socket_present; then
    echo "FAIL: RuntimeService stop left abstract control socket" >&2
    failures=$((failures + 1))
  else
    echo "stop=control_socket_absent"
  fi
  assert_cleanup_log stop
  sleep 1
}

echo "# SAKAMOTO-16 Android RuntimeService repeated lifecycle residue POC"
echo "run_id=$RUN_ID"
echo "cycles=$CYCLES"
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

echo "seeding pre-existing IPv4/IPv6 chains and top-level jumps"
seed_preexisting_hooks
capture_state preexisting-hooks
assert_hooks_present preexisting
assert_single_family_jumps preexisting

for cycle in $(seq 1 "$CYCLES"); do
  echo "cycle=$cycle start"
  start_runtime
  capture_state "cycle-${cycle}-started"
  assert_hooks_present "cycle_${cycle}_start"
  assert_single_family_jumps "cycle_${cycle}_start"
  if [[ "$cycle" == "1" ]]; then
    if app_read "$RUNTIME_LOG" | rg -q 'Chain already exists'; then
      echo "cycle_1=preexisting_chain_idempotent_install_observed"
    else
      echo "FAIL: pre-existing chain idempotent install log missing" >&2
      failures=$((failures + 1))
    fi
  fi
  stop_runtime
  capture_state "cycle-${cycle}-stopped"
done

echo "force-stop and fresh recovery smoke"
adb_cmd shell am force-stop "$PACKAGE"
sleep 1
start_runtime
capture_state force-stop-started
assert_hooks_present force_stop_start
adb_cmd shell am force-stop "$PACKAGE"
sleep 3
if wait_for_no_daemon; then
  echo "force_stop=daemon_absent_without_manual_cleanup"
else
  echo "FAIL: force-stop left daemon" >&2
  failures=$((failures + 1))
fi
capture_state force-stopped
assert_hooks_absent force_stop
if socket_present; then
  echo "FAIL: force-stop left abstract control socket" >&2
  failures=$((failures + 1))
else
  echo "force_stop=control_socket_absent"
fi
if app_read "$RUNTIME_LOG" | rg -q 'parent monitor detected reparenting'; then
  echo "force_stop=parent_monitor_detected_reparenting"
else
  echo "FAIL: parent monitor log missing" >&2
  failures=$((failures + 1))
fi

start_runtime
capture_state recovered-started
assert_hooks_present recovery
assert_single_family_jumps recovery
stop_runtime
capture_state recovered-stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-16 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-16 repeated lifecycle residue"
echo "result_dir=$RESULT_DIR"
