#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: validate Android Rust persistent client stale-handle reconnect.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
WAIT_SECONDS="${WAIT_SECONDS:-45}"
WARMUP_SECONDS="${WARMUP_SECONDS:-5}"
VPP_STAGE_FOR_ID="${VPP_STAGE_DIR:-$POC_DIR/work/android-vpp-api-stage}"
if [[ ! -x "$VPP_STAGE_FOR_ID/bin/vpp" ]]; then
  VPP_STAGE_FOR_ID="$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage"
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-11-rust-reconnect-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RECONNECT_LOG="files/vpp/logs/rust-vapi-reconnect-probe.log"
STALE_MARKER="files/vpp/runtime/reconnect-stale"
REOPEN_MARKER="files/vpp/runtime/reconnect-reopen"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
failures=0
package_uid=""

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

wait_for_pid() {
  local kind="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local pid=""
  while (( SECONDS < deadline )); do
    if [[ "$kind" == "vpp" ]]; then
      pid="$(vpp_process_pid || true)"
    else
      pid="$(package_process_pid || true)"
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_api_socket() {
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if app_cmd test -S files/vpp/runtime/api.sock >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_log() {
  local pattern="$1"
  local deadline=$((SECONDS + WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if app_read "$RECONNECT_LOG" | rg -q "$pattern"; then
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
  app_cmd ls -la files/vpp/runtime files/vpp/logs | tr -d '\r' \
    >"$dir/app-runtime-listing.txt" 2>&1 || true
  if [[ -n "$app_pid" ]]; then
    adb_cmd shell cat "/proc/$app_pid/status" | tr -d '\r' \
      >"$dir/app-status.txt" 2>&1 || true
  fi
  if [[ -n "$vpp_pid" ]]; then
    adb_cmd shell cat "/proc/$vpp_pid/status" | tr -d '\r' \
      >"$dir/vpp-status.txt" 2>&1 || true
  fi
  if app_cmd test -S files/vpp/runtime/api.sock; then
    echo "api_socket=present" >"$dir/api-socket.txt"
  else
    echo "api_socket=absent" >"$dir/api-socket.txt"
  fi
  app_read "$RECONNECT_LOG" >"$dir/rust-vapi-reconnect-probe.log"
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

echo "# SAKAMOTO-11 Android Rust persistent client reconnect POC"
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
app_cmd rm -f "$RECONNECT_LOG" "$STALE_MARKER" "$REOPEN_MARKER" >/dev/null 2>&1 || true
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
battery_after_unplug="$(adb_cmd shell dumpsys battery | tr -d '\r')"
printf '%s\n' "$battery_after_unplug" >"$RESULT_DIR/battery-after-unplug.txt"
if ! grep -Eq 'USB powered: false|USB powered=false' <<<"$battery_after_unplug"; then
  echo "USB power simulation failed" >&2
  exit 1
fi

if ! start_vpp; then
  capture_state start-failed "$(package_process_pid || true)" "$(vpp_process_pid || true)"
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

adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez rustReconnectProbe true --ei durationSeconds "$WAIT_SECONDS" >/dev/null
if ! wait_for_log '^ready=1$'; then
  echo "FAIL: persistent Rust client did not reach ready" >&2
  capture_state reconnect-ready-failed "$initial_app_pid" "$initial_vpp_pid"
  exit 1
fi
echo "persistent_client=ready"
capture_state before-vpp-stop "$initial_app_pid" "$initial_vpp_pid"

adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null
sleep 2
capture_state after-vpp-stop "$initial_app_pid" ""
if ! grep -q '^api_socket=absent$' "$RESULT_DIR/after-vpp-stop/api-socket.txt"; then
  echo "FAIL: API socket remained after VPP stop" >&2
  failures=$((failures + 1))
fi
app_cmd touch "$STALE_MARKER"
if ! wait_for_log '^stale_status_rc='; then
  echo "FAIL: stale handle did not report status result" >&2
  failures=$((failures + 1))
else
  stale_line="$(app_read "$RECONNECT_LOG" | rg '^stale_status_rc=' | tail -1)"
  if printf '%s\n' "$stale_line" | rg -q '=0$'; then
    echo "FAIL: stale handle status unexpectedly succeeded" >&2
    failures=$((failures + 1))
  else
    echo "stale_handle=failed_as_expected $stale_line"
  fi
fi
capture_state after-stale-handle "$initial_app_pid" ""

if ! start_vpp; then
  capture_state restart-failed "$(package_process_pid || true)" "$(vpp_process_pid || true)"
  exit 1
fi
restart_vpp_pid="$(vpp_process_pid || true)"
restart_app_pid="$(package_process_pid || true)"
if [[ ! "$restart_vpp_pid" =~ ^[0-9]+$ || ! "$restart_app_pid" =~ ^[0-9]+$ ]]; then
  echo "FAIL: missing restarted app/VPP PID" >&2
  exit 1
fi
if [[ "$restart_vpp_pid" == "$initial_vpp_pid" ]]; then
  echo "FAIL: restart reused original VPP PID" >&2
  failures=$((failures + 1))
else
  echo "restart_vpp_pid=$restart_vpp_pid"
fi
app_cmd touch "$REOPEN_MARKER"
if ! wait_for_log '^result=pass rc=0$'; then
  echo "FAIL: fresh reconnect result did not pass" >&2
  failures=$((failures + 1))
else
  echo "fresh_handle=pass"
fi
capture_state after-reconnect "$restart_app_pid" "$restart_vpp_pid"
adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' \
  >"$RESULT_DIR/final-logcat.txt"

cleanup
if ! grep -Eq 'USB powered: true|USB powered=true' "$RESULT_DIR/battery-after-reset.txt"; then
  echo "cleanup FAIL: USB power override was not reset" >&2
  failures=$((failures + 1))
fi
if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-11 Rust persistent reconnect failures=$failures" >&2
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-11 Android Rust persistent client stale-handle reconnect"
echo "result_dir=$RESULT_DIR"
