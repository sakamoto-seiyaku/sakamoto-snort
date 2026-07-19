#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: observe Android APK upgrade/rollback while RuntimeService is active.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-20-apk-upgrade-rollback-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"

OLD_VERSION_NAME="0.1-poc-old"
NEW_VERSION_NAME="0.2-poc-new"
OLD_VERSION_CODE=1
NEW_VERSION_CODE=2
OLD_APK="$RESULT_DIR/snort-vpn-lite-old.apk"
NEW_APK="$RESULT_DIR/snort-vpn-lite-new.apk"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
fatal_failures=0
transition_residue=0

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
    if app_read "$RUNTIME_LOG" | rg -q "$pattern"; then return 0; fi
    sleep 1
  done
  return 1
}

wait_for_no_daemon() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if [[ -z "$(daemon_pids)" ]]; then return 0; fi
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
  for table in iptables ip6tables; do
    adb_su "/system/bin/$table -w -D INPUT -j sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -D OUTPUT -j sucre-snort_OUTPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -F sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -F sucre-snort_OUTPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -X sucre-snort_INPUT" >/dev/null 2>&1 || true
    adb_su "/system/bin/$table -w -X sucre-snort_OUTPUT" >/dev/null 2>&1 || true
  done
}

package_dump() {
  adb_cmd shell dumpsys package "$PACKAGE" | tr -d '\r'
}

capture_identity() {
  {
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(resolve_adb_serial)"
    echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
    echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    echo "build_fingerprint=$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "abi=$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
    echo "old_apk_sha256=$(sha256sum "$OLD_APK")"
    echo "new_apk_sha256=$(sha256sum "$NEW_APK")"
    echo "daemon_artifact_sha256=$(sha256sum "$REPO_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so")"
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
  package_dump >"$dir/package.txt"
  adb_cmd shell dumpsys activity services "$PACKAGE" | tr -d '\r' >"$dir/activity-services.txt"
  adb_cmd shell dumpsys battery | tr -d '\r' >"$dir/battery.txt"
  adb_cmd logcat -d -s SnortRuntimeService:I SnortVpnLite:I '*:S' | tr -d '\r' \
    >"$dir/logcat.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

assert_active() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then echo "$phase=root_daemon_present"; else echo "FAIL: $phase daemon absent" >&2; fatal_failures=$((fatal_failures + 1)); fi
  if socket_present; then echo "$phase=control_socket_present"; else echo "FAIL: $phase control socket absent" >&2; fatal_failures=$((fatal_failures + 1)); fi
  if hooks_present; then echo "$phase=nfqueue_hooks_present"; else echo "FAIL: $phase NFQUEUE hooks absent" >&2; fatal_failures=$((fatal_failures + 1)); fi
  local count
  count="$(top_level_jump_count)"
  if [[ "$count" == "4" ]]; then echo "$phase=top_level_jump_count_4"; else echo "FAIL: $phase expected 4 top-level jumps, got $count" >&2; fatal_failures=$((fatal_failures + 1)); fi
}

assert_version() {
  local phase="$1"
  local version_name="$2"
  local dump
  dump="$(package_dump)"
  if rg -q "versionName=$version_name" <<<"$dump"; then
    echo "$phase=version_$version_name"
  else
    echo "FAIL: $phase expected versionName=$version_name" >&2
    fatal_failures=$((fatal_failures + 1))
  fi
}

assert_transition_clean() {
  local phase="$1"
  local clean=1
  if [[ -n "$(daemon_pids)" ]]; then echo "$phase=daemon_residue"; clean=0; else echo "$phase=no_root_daemon"; fi
  if socket_present; then echo "$phase=control_socket_residue"; clean=0; else echo "$phase=control_socket_absent"; fi
  if hooks_present; then echo "$phase=nfqueue_hook_residue"; clean=0; else echo "$phase=nfqueue_hooks_absent"; fi
  if [[ "$clean" == "0" ]]; then
    transition_residue=1
    echo "$phase=automatic_cleanup_HOLD"
  else
    echo "$phase=automatic_cleanup_pass"
  fi
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
    exit_code=1
  fi
  if [[ "$fatal_failures" != "0" && "$exit_code" == "0" ]]; then exit_code=1; fi
  return "$exit_code"
}

trap cleanup EXIT

build_variants() {
  echo "building old APK versionCode=$OLD_VERSION_CODE versionName=$OLD_VERSION_NAME"
  APK_VERSION_CODE="$OLD_VERSION_CODE" APK_VERSION_NAME="$OLD_VERSION_NAME" \
    bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
  cp "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk" "$OLD_APK"

  echo "building new APK versionCode=$NEW_VERSION_CODE versionName=$NEW_VERSION_NAME"
  APK_VERSION_CODE="$NEW_VERSION_CODE" APK_VERSION_NAME="$NEW_VERSION_NAME" \
    bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
  cp "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk" "$NEW_APK"
}

install_old() {
  adb_cmd install -d -r "$OLD_APK"
}

install_new() {
  adb_cmd install -r "$NEW_APK"
}

start_runtime() {
  app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
  if ! wait_for_runtime_log 'runtime_start_result=pass$'; then
    echo "FAIL: RuntimeService start failed" >&2
    fatal_failures=$((fatal_failures + 1))
    return 1
  fi
}

stop_runtime() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
  if wait_for_no_daemon; then echo "$1=no_root_daemon"; else echo "FAIL: $1 daemon remains" >&2; fatal_failures=$((fatal_failures + 1)); fi
  if socket_present; then echo "FAIL: $1 control socket remains" >&2; fatal_failures=$((fatal_failures + 1)); else echo "$1=control_socket_absent"; fi
  if hooks_present; then echo "FAIL: $1 NFQUEUE hooks remain" >&2; fatal_failures=$((fatal_failures + 1)); else echo "$1=nfqueue_hooks_absent"; fi
  sleep 1
}

echo "# SAKAMOTO-20 Android APK upgrade/rollback hook residue POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
device_preflight
stop_existing
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-after-unplug.txt"
if ! rg -q 'USB powered: false|USB powered=false' "$RESULT_DIR/battery-after-unplug.txt"; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "building versioned APK pair"
bash "$REPO_ROOT/dev/dev-build-ndk.sh"
build_variants
capture_identity

echo "installing old APK and starting RuntimeService"
install_old
capture_state old-installed
assert_version old-installed "$OLD_VERSION_NAME"
start_runtime
capture_state old-active-before-upgrade
assert_version old-active-before-upgrade "$OLD_VERSION_NAME"
assert_active old-active-before-upgrade

echo "upgrading to new APK while old RuntimeService is active"
install_new
capture_state new-installed-after-upgrade
assert_version new-installed-after-upgrade "$NEW_VERSION_NAME"
if wait_for_no_daemon; then echo "upgrade=no_root_daemon"; else echo "upgrade=daemon_residue"; fi
assert_transition_clean upgrade
if [[ "$transition_residue" == "1" ]]; then
  echo "manual cleanup after upgrade residue"
  stop_existing
fi

echo "starting and stopping new APK after upgrade"
start_runtime
capture_state new-active-after-upgrade
assert_version new-active-after-upgrade "$NEW_VERSION_NAME"
assert_active new-active-after-upgrade
stop_runtime new-stop

echo "starting new APK before rollback"
start_runtime
capture_state new-active-before-rollback
assert_version new-active-before-rollback "$NEW_VERSION_NAME"
assert_active new-active-before-rollback

echo "rolling back to old APK while new RuntimeService is active"
install_old
capture_state old-installed-after-rollback
assert_version old-installed-after-rollback "$OLD_VERSION_NAME"
if wait_for_no_daemon; then echo "rollback=no_root_daemon"; else echo "rollback=daemon_residue"; fi
assert_transition_clean rollback
if [[ "$transition_residue" == "1" ]]; then
  echo "manual cleanup after rollback residue"
  stop_existing
fi

echo "starting and stopping old APK after rollback"
start_runtime
capture_state old-active-after-rollback
assert_version old-active-after-rollback "$OLD_VERSION_NAME"
assert_active old-active-after-rollback
stop_runtime old-stop

if [[ "$fatal_failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-20 harness/product critical failures=$fatal_failures" >&2
  exit 1
fi
if [[ "$transition_residue" == "0" ]]; then
  echo "PASS: SAKAMOTO-20 APK upgrade/rollback and hook residue boundary"
  echo "decision=upgrade/rollback cleanup GO on this device"
else
  echo "PASS: SAKAMOTO-20 experiment complete"
  echo "decision=upgrade/rollback automatic cleanup HOLD; residue was captured and manually cleaned"
fi
echo "result_dir=$RESULT_DIR"
