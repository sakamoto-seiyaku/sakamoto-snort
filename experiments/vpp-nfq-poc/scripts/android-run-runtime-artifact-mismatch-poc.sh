#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: exercise wrong-ABI, altered-identity, and valid-artifact startup gates.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-25-runtime-artifact-mismatch-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUNTIME_LOG="files/logs/runtime-service.log"
NORMAL_ARTIFACT="$REPO_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0

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
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' | tr -d '\r' >"$dir/processes.txt"
  hook_snapshot >"$dir/hooks.txt"
  adb_su 'grep -F "sucre-snort-control-vnext" /proc/net/unix 2>/dev/null || true' \
    | tr -d '\r' >"$dir/control-socket.txt"
  app_read "$RUNTIME_LOG" >"$dir/runtime-service.log"
}

build_install() {
  local artifact="$1"
  echo "building APK artifact=$artifact"
  SNORT_ANDROID_DAEMON_ARTIFACT="$artifact" \
    bash "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
  bash "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
  adb_cmd shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
}

start_runtime() {
  app_cmd rm -f "$RUNTIME_LOG" >/dev/null 2>&1 || true
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStart true >/dev/null
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

echo "# SAKAMOTO-25 RuntimeService artifact mismatch POC"
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

echo "wrong ABI / invalid ELF"
build_install /bin/true
{
  echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
  echo "packaged_artifact_sha256=$(sha256sum /bin/true)"
} >"$RESULT_DIR/wrong-abi-identity.txt"
start_runtime
if wait_for_log 'runtime_start_result=fail'; then
  echo "wrong_abi=start_failure_logged"
else
  echo "FAIL: wrong ABI did not fail startup" >&2
  failures=$((failures + 1))
fi
capture_state wrong-abi
assert_no_residue wrong_abi

echo "same ABI / altered HELLO build identity"
altered_artifact="$RESULT_DIR/altered-identity-daemon.so"
cp "$NORMAL_ARTIFACT" "$altered_artifact"
build_id_offset="$(LC_ALL=C grep -abo --binary-files=text 'ndk-r29-' "$altered_artifact" | head -n 1 | cut -d: -f1)"
if [[ -z "$build_id_offset" ]]; then
  echo "FAIL: daemon build identity string not found" >&2
  failures=$((failures + 1))
else
  printf 'f' | dd of="$altered_artifact" bs=1 seek=$((build_id_offset + 8)) conv=notrunc 2>/dev/null
  echo "altered_build_id_offset=$build_id_offset"
fi
build_install "$altered_artifact"
{
  echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
  echo "packaged_artifact_sha256=$(sha256sum "$altered_artifact")"
} >"$RESULT_DIR/altered-identity.txt"
start_runtime
if wait_for_log 'runtime_start_result=pass$'; then
  echo "altered_identity=accepted_current_gate_HOLD"
  capture_state altered-identity-started
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
  sleep 2
  capture_state altered-identity-stopped
  assert_no_residue altered_identity_stop
else
  echo "altered_identity=rejected_current_gate_GO"
  capture_state altered-identity-failed
  assert_no_residue altered_identity_failed
fi

echo "same ABI / HELLO protocol contract mismatch"
contract_artifact="$RESULT_DIR/contract-mismatch-daemon.so"
cp "$NORMAL_ARTIFACT" "$contract_artifact"
contract_offset="$(LC_ALL=C grep -abo 'control-vnext' "$contract_artifact" | tail -n 1 | cut -d: -f1)"
if [[ -z "$contract_offset" ]]; then
  echo "FAIL: daemon HELLO protocol string not found" >&2
  failures=$((failures + 1))
else
  printf 'x' | dd of="$contract_artifact" bs=1 seek=$((contract_offset + 8)) conv=notrunc 2>/dev/null
  echo "contract_protocol_offset=$contract_offset"
fi
build_install "$contract_artifact"
{
  echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
  echo "packaged_artifact_sha256=$(sha256sum "$contract_artifact")"
} >"$RESULT_DIR/contract-mismatch.txt"
start_runtime
if wait_for_log 'hello_result=fail reason=contract_mismatch'; then
  echo "contract_mismatch=detected"
else
  echo "FAIL: HELLO contract mismatch was not logged" >&2
  failures=$((failures + 1))
fi
if wait_for_log 'runtime_start_result=fail'; then
  echo "contract_mismatch=start_failure_logged"
else
  echo "FAIL: HELLO contract mismatch did not fail startup" >&2
  failures=$((failures + 1))
fi
capture_state contract-mismatch
assert_no_residue contract_mismatch

echo "valid artifact recovery"
build_install "$NORMAL_ARTIFACT"
start_runtime
if wait_for_log 'runtime_start_result=pass$'; then echo "valid_recovery=runtime_start_pass"; else echo "FAIL: valid artifact recovery did not start" >&2; failures=$((failures + 1)); fi
capture_state valid-recovery-started
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez runtimeStop true >/dev/null
sleep 2
capture_state valid-recovery-stopped
assert_no_residue valid_recovery

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-25 harness failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-25 RuntimeService artifact mismatch boundary"
echo "result_dir=$RESULT_DIR"
