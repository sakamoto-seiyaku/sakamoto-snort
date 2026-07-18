#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: validate Android VPP child death, cleanup, and restart boundaries.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-30}"
WARMUP_SECONDS="${WARMUP_SECONDS:-5}"
VPP_STAGE_FOR_ID="${VPP_STAGE_DIR:-$POC_DIR/work/android-vpp-api-stage}"
if [[ ! -x "$VPP_STAGE_FOR_ID/bin/vpp" ]]; then
  VPP_STAGE_FOR_ID="$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage"
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-10-abnormal-restart-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUST_CONTROL_LOG="files/vpp/logs/rust-vapi-control-probe.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0
package_uid=""
initial_vpp_pid=""
restart_vpp_pid=""

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null | tr -d '\r' || true
}

ps_snapshot() {
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r'
}

package_process_pid() {
  ps_snapshot | awk -v package="$PACKAGE" '$5 == package { print $2; exit }'
}

vpp_process_pid() {
  ps_snapshot | awk -v uid="$package_uid" '$1 == uid && $5 == "vpp" { print $2; exit }'
}

pid_present() {
  local pid="$1"
  ps_snapshot | awk -v pid="$pid" '$2 == pid { found = 1 } END { exit found ? 0 : 1 }'
}

wait_for_pid() {
  local kind="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local pid=""
  while (( SECONDS < deadline )); do
    if [[ "$kind" == "vpp" ]]; then
      pid="$(vpp_process_pid)"
    else
      pid="$(package_process_pid)"
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_pid_gone() {
  local pid="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! pid_present "$pid"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

api_socket_present() {
  app_cmd test -S files/vpp/runtime/api.sock >/dev/null 2>&1
}

wait_for_api_socket() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if api_socket_present; then
      return 0
    fi
    sleep 1
  done
  return 1
}

stop_app() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

capture_identity() {
  {
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(resolve_adb_serial)"
    echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
    echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    echo "build_fingerprint=$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "abi=$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
    echo "kernel=$(adb_cmd shell uname -a | tr -d '\r')"
    echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
    echo "vpp_sha256=$(sha256sum "$VPP_STAGE_FOR_ID/bin/vpp")"
    echo "wait_seconds=$WAIT_SECONDS warmup_seconds=$WARMUP_SECONDS"
    echo "## package"
    adb_cmd shell dumpsys package "$PACKAGE" | rg 'userId=|versionName=' | tr -d '\r'
    echo "## battery before unplug"
    adb_cmd shell dumpsys battery | tr -d '\r'
    echo "## power before unplug"
    adb_cmd shell dumpsys power | tr -d '\r'
    echo "## deviceidle before unplug"
    adb_cmd shell dumpsys deviceidle | tr -d '\r'
    echo "## thermal before unplug"
    adb_cmd shell dumpsys thermalservice | tr -d '\r'
  } >"$RESULT_DIR/device-identity.txt"
}

capture_state() {
  local name="$1"
  local app_pid="${2:-}"
  local vpp_pid="${3:-}"
  local dir="$RESULT_DIR/$name"
  mkdir -p "$dir"
  ps_snapshot >"$dir/processes.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' \
    >"$dir/logcat.txt"
  adb_cmd shell dumpsys battery | tr -d '\r' >"$dir/battery.txt"
  adb_cmd shell dumpsys power | tr -d '\r' >"$dir/power.txt"
  adb_cmd shell dumpsys deviceidle | tr -d '\r' >"$dir/deviceidle.txt"
  adb_cmd shell dumpsys thermalservice | tr -d '\r' >"$dir/thermalservice.txt"
  adb_cmd shell ip -o link | tr -d '\r' >"$dir/ip-link.txt" 2>&1 || true
  adb_cmd shell dumpsys connectivity | tr -d '\r' >"$dir/connectivity.txt" 2>&1 || true
  app_cmd ls -la files/vpp/runtime files/vpp/logs | tr -d '\r' \
    >"$dir/app-runtime-listing.txt" 2>&1 || true
  if [[ -n "$app_pid" ]]; then
    adb_cmd shell ls -la "/proc/$app_pid/fd" | tr -d '\r' \
      >"$dir/app-fd.txt" 2>&1 || true
    adb_cmd shell cat "/proc/$app_pid/status" | tr -d '\r' \
      >"$dir/app-status.txt" 2>&1 || true
  fi
  if [[ -n "$vpp_pid" ]]; then
    adb_cmd shell ls -la "/proc/$vpp_pid/fd" | tr -d '\r' \
      >"$dir/vpp-fd.txt" 2>&1 || true
    adb_cmd shell cat "/proc/$vpp_pid/status" | tr -d '\r' \
      >"$dir/vpp-status.txt" 2>&1 || true
  fi
  if api_socket_present; then
    echo "api_socket=present" >"$dir/api-socket.txt"
  else
    echo "api_socket=absent" >"$dir/api-socket.txt"
  fi
  app_read files/vpp/logs/vpp-stdout.log >"$dir/vpp-stdout.log"
  app_read files/vpp/logs/vpp-cli.log >"$dir/vpp-cli.log"
}

start_vpp() {
  adb_cmd logcat -c
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true --es mode vpp --ez enableIpv6 true >/dev/null
  sleep "$WARMUP_SECONDS"
  if ! wait_for_api_socket; then
    echo "FAIL: VPP API socket did not appear" >&2
    return 1
  fi
  if ! wait_for_pid vpp >/dev/null; then
    echo "FAIL: VPP process did not appear" >&2
    return 1
  fi
}

run_rust_probe() {
  local name="$1"
  local expected_pass="$2"
  local dir="$RESULT_DIR/$name"
  local deadline line
  mkdir -p "$dir"
  app_cmd rm -f "$RUST_CONTROL_LOG" >/dev/null 2>&1 || true
  adb_cmd logcat -c
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez rustControlProbe true --ei blockOwnerUid "$package_uid" --ei rounds 1 >/dev/null
  deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if app_read "$RUST_CONTROL_LOG" | rg -q '^result='; then
      break
    fi
    sleep 1
  done
  line="$(app_read "$RUST_CONTROL_LOG")"
  printf '%s\n' "$line" >"$dir/rust-vapi-control-probe.log"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' \
    >"$dir/logcat.txt"
  if [[ "$expected_pass" == "true" ]]; then
    if ! printf '%s\n' "$line" | rg -q '^result=pass rc=0$'; then
      echo "$name FAIL: expected Rust control pass"
      failures=$((failures + 1))
      return 1
    fi
    if ! printf '%s\n' "$line" | rg -q "^abi_version=1 uid=$package_uid "; then
      echo "$name FAIL: Rust probe UID/ABI identity"
      failures=$((failures + 1))
      return 1
    fi
    echo "$name PASS: Rust typed control is available"
    return 0
  fi
  if printf '%s\n' "$line" | rg -q '^result=pass rc=0$'; then
    echo "$name FAIL: control unexpectedly survived VPP death"
    failures=$((failures + 1))
    return 1
  fi
  echo "$name PASS: control unavailable after VPP death (expected boundary)"
  return 0
}

cleanup() {
  stop_app || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    echo "battery_reset=done"
    battery_unplugged=0
  fi
  ps_snapshot >"$RESULT_DIR/processes-after-cleanup.txt" || true
  adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-after-reset.txt" || true
  if [[ -n "$package_uid" ]]; then
    local residual
    residual="$(awk -v uid="$package_uid" '$1 == uid && ($5 == "vpp" || index($5, "com.sakamoto.snort.vpnlite") == 1)' \
      "$RESULT_DIR/processes-after-cleanup.txt" 2>/dev/null || true)"
    if [[ -n "$residual" ]]; then
      echo "cleanup residual app-UID process:" >&2
      printf '%s\n' "$residual" >&2
      failures=$((failures + 1))
    fi
  fi
}
trap cleanup EXIT INT TERM

echo "# SAKAMOTO-10 Android VPP abnormal child exit and stop/restart POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
capture_identity

package_uid="$(app_cmd id -u | tr -d '\r\n')"
if [[ ! "$package_uid" =~ ^[0-9]+$ ]]; then
  echo "invalid package uid: $package_uid" >&2
  exit 1
fi
echo "package_uid=$package_uid"

stop_app
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
battery_after_unplug="$(adb_cmd shell dumpsys battery | tr -d '\r')"
printf '%s\n' "$battery_after_unplug" >"$RESULT_DIR/battery-after-unplug.txt"
if ! grep -Eq 'USB powered: false|USB powered=false' <<<"$battery_after_unplug"; then
  echo "USB power simulation failed" >&2
  exit 1
fi

if ! start_vpp; then
  capture_state start-failed "$(package_process_pid)" "$(vpp_process_pid)"
  exit 1
fi
initial_vpp_pid="$(vpp_process_pid || true)"
initial_app_pid="$(package_process_pid || true)"
if [[ ! "$initial_vpp_pid" =~ ^[0-9]+$ || ! "$initial_app_pid" =~ ^[0-9]+$ ]]; then
  echo "FAIL: missing initial app/VPP PID" >&2
  exit 1
fi
echo "initial_app_pid=$initial_app_pid"
echo "initial_vpp_pid=$initial_vpp_pid"
capture_state before-vpp-kill "$initial_app_pid" "$initial_vpp_pid"
run_rust_probe baseline true

echo "## abnormal VPP exit as ordinary app UID"
if ! app_cmd /system/bin/kill -TERM "$initial_vpp_pid"; then
  echo "kill_command=/system/bin/kill failed; retrying app PATH kill" >&2
  app_cmd kill -TERM "$initial_vpp_pid"
fi
echo "kill_signal=TERM kill_target=$initial_vpp_pid kill_identity=$(app_cmd id | tr -d '\r')"
if ! wait_for_pid_gone "$initial_vpp_pid"; then
  echo "FAIL: VPP process survived app-UID SIGTERM" >&2
  failures=$((failures + 1))
else
  echo "vpp_exit=observed"
fi
app_pid_after_kill="$(package_process_pid || true)"
capture_state after-vpp-kill "$app_pid_after_kill" "$initial_vpp_pid"
run_rust_probe after-vpp-kill false

adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null
sleep 2
capture_state after-stop "$app_pid_after_kill" ""

if ! start_vpp; then
  capture_state restart-failed "$(package_process_pid)" "$(vpp_process_pid)"
  exit 1
fi
restart_vpp_pid="$(vpp_process_pid || true)"
restart_app_pid="$(package_process_pid || true)"
if [[ ! "$restart_vpp_pid" =~ ^[0-9]+$ || ! "$restart_app_pid" =~ ^[0-9]+$ ]]; then
  echo "FAIL: missing restarted app/VPP PID" >&2
  exit 1
fi
if [[ "$restart_vpp_pid" == "$initial_vpp_pid" ]]; then
  echo "FAIL: restart reused the original VPP PID; cannot prove a new child" >&2
  failures=$((failures + 1))
else
  echo "restart_vpp_pid=$restart_vpp_pid"
fi
capture_state after-restart "$restart_app_pid" "$restart_vpp_pid"
run_rust_probe after-restart true

adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' \
  >"$RESULT_DIR/final-logcat.txt"
capture_state before-final-cleanup "$restart_app_pid" "$restart_vpp_pid"
cleanup
if ! grep -Eq 'USB powered: true|USB powered=true' "$RESULT_DIR/battery-after-reset.txt"; then
  echo "cleanup FAIL: USB power override was not reset" >&2
  failures=$((failures + 1))
fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-10 abnormal restart failures=$failures" >&2
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-10 Android VPP abnormal child exit and stop/restart"
echo "result_dir=$RESULT_DIR"
