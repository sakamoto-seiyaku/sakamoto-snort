#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify the APK-pinned daemon artifact SHA-256 gate before su launch.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-26-runtime-artifact-hash-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"
NORMAL_ARTIFACT="$REPO_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
battery_unplugged=0

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
  while (( attempts < 30 )); do
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
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' \
    | tr -d '\r' >"$dir/processes.txt"
  hook_snapshot >"$dir/hooks.txt"
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"$dir/control-socket.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

build_install() {
  local artifact="$1"
  local expected_hash="$2"
  echo "building APK artifact=$artifact expected_sha256=$expected_hash"
  SNORT_ANDROID_DAEMON_ARTIFACT="$artifact" \
  SNORT_EXPECTED_DAEMON_SHA256="$expected_hash" \
    bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
  bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
  adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
}

start_runtime() {
  app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
}

assert_running() {
  local phase="$1"
  if [[ -z "$(daemon_pids)" ]]; then
    echo "FAIL: $phase daemon missing" >&2
    failures=$((failures + 1))
  else
    echo "$phase=root_daemon_present"
  fi
  if socket_present; then echo "$phase=control_socket_present"; else echo "FAIL: $phase socket missing" >&2; failures=$((failures + 1)); fi
  if hooks_present; then echo "$phase=nfqueue_hooks_present"; else echo "FAIL: $phase hooks missing" >&2; failures=$((failures + 1)); fi
}

assert_no_residue() {
  local phase="$1"
  if [[ -n "$(daemon_pids)" ]]; then echo "FAIL: $phase daemon remains" >&2; failures=$((failures + 1)); else echo "$phase=no_root_daemon"; fi
  if socket_present; then echo "FAIL: $phase control socket remains" >&2; failures=$((failures + 1)); else echo "$phase=control_socket_absent"; fi
  if hooks_present; then echo "FAIL: $phase NFQUEUE hooks remain" >&2; failures=$((failures + 1)); else echo "$phase=nfqueue_hooks_absent"; fi
}

cleanup() {
  local exit_code=$?
  stop_existing || true
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

echo "# SAKAMOTO-26 RuntimeService artifact hash gate POC"
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
cp "$NORMAL_ARTIFACT" "$RESULT_DIR/normal-daemon.so"
normal_sha="$(sha256sum "$NORMAL_ARTIFACT" | awk '{print $1}')"
echo "normal_daemon_sha256=$normal_sha"

echo "normal artifact / pinned hash match"
build_install "$NORMAL_ARTIFACT" "$normal_sha"
start_runtime
if wait_for_log 'artifact_hash_result=pass'; then echo "normal=artifact_hash_pass"; else echo "FAIL: normal hash did not pass" >&2; failures=$((failures + 1)); fi
if wait_for_log 'runtime_start_result=pass$'; then echo "normal=runtime_start_pass"; else echo "FAIL: normal runtime did not start" >&2; failures=$((failures + 1)); fi
assert_running normal_running
capture_state normal-running
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state normal-stopped
assert_no_residue normal_stopped

echo "altered artifact / pinned normal hash mismatch"
altered_artifact="$RESULT_DIR/altered-daemon.so"
cp "$NORMAL_ARTIFACT" "$altered_artifact"
build_id_offset="$(LC_ALL=C grep -abo --binary-files=text 'ndk-r29-' "$altered_artifact" | head -n 1 | cut -d: -f1)"
if [[ -z "$build_id_offset" ]]; then
  echo "FAIL: daemon build identity string not found" >&2
  failures=$((failures + 1))
else
  printf 'f' | dd of="$altered_artifact" bs=1 seek=$((build_id_offset + 8)) conv=notrunc 2>/dev/null
  echo "altered_build_id_offset=$build_id_offset"
fi
altered_sha="$(sha256sum "$altered_artifact" | awk '{print $1}')"
echo "altered_daemon_sha256=$altered_sha"
build_install "$altered_artifact" "$normal_sha"
start_runtime
if wait_for_log 'runtime_start_result=fail reason=artifact_hash_mismatch'; then
  echo "altered=artifact_hash_mismatch_detected"
else
  echo "FAIL: altered artifact hash mismatch was not detected" >&2
  failures=$((failures + 1))
fi
capture_state altered
if app_read "$RUNTIME_LOG" | rg -q 'root_launch=started'; then
  echo "FAIL: altered artifact launched root daemon" >&2
  failures=$((failures + 1))
else
  echo "altered=no_root_launch_before_hash_gate"
fi
assert_no_residue altered

echo "normal artifact recovery"
build_install "$NORMAL_ARTIFACT" "$normal_sha"
start_runtime
if wait_for_log 'artifact_hash_result=pass'; then echo "recovery=artifact_hash_pass"; else echo "FAIL: recovery hash did not pass" >&2; failures=$((failures + 1)); fi
if wait_for_log 'runtime_start_result=pass$'; then echo "recovery=runtime_start_pass"; else echo "FAIL: recovery runtime did not start" >&2; failures=$((failures + 1)); fi
assert_running recovery_running
capture_state recovery-running
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state recovery-stopped
assert_no_residue recovery_stopped

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-26 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-26 RuntimeService artifact hash gate"
echo "result_dir=$RESULT_DIR"
