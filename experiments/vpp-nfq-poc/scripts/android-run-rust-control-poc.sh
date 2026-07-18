#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: validate Rust -> C ABI shim -> packaged VAPI control on Android.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
ROUNDS="${ROUNDS:-5}"
WARMUP_SECONDS="${WARMUP_SECONDS:-5}"
WAIT_SECONDS="${WAIT_SECONDS:-20}"
VPP_STAGE_FOR_ID="${VPP_STAGE_DIR:-$POC_DIR/work/android-vpp-api-stage}"
if [[ ! -x "$VPP_STAGE_FOR_ID/bin/vpp" ]]; then
  VPP_STAGE_FOR_ID="$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage"
fi

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-9-rust-control-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
RUST_CONTROL_LOG="files/vpp/logs/rust-vapi-control-probe.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/rounds"
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
    echo "vpp_stage=$VPP_STAGE_FOR_ID"
    echo "vpp_sha256=$(sha256sum "$VPP_STAGE_FOR_ID/bin/vpp")"
    echo "rounds=$ROUNDS warmup_seconds=$WARMUP_SECONDS wait_seconds=$WAIT_SECONDS"
    echo "## package uid"
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

capture_round() {
  local round="$1"
  local dir="$RESULT_DIR/rounds/$(printf '%02d' "$round")"
  mkdir -p "$dir"
  printf '%s\n' "$(app_read "$RUST_CONTROL_LOG")" >"$dir/rust-vapi-control-probe.log"
  printf '%s\n' "$(adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r')" \
    >"$dir/logcat.txt"
  printf '%s\n' "$(adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r')" \
    >"$dir/processes.txt"
  printf '%s\n' "$(adb_cmd shell dumpsys battery | tr -d '\r')" >"$dir/battery.txt"
  printf '%s\n' "$(adb_cmd shell dumpsys power | tr -d '\r')" >"$dir/power.txt"
  printf '%s\n' "$(adb_cmd shell dumpsys deviceidle | tr -d '\r')" >"$dir/deviceidle.txt"
  printf '%s\n' "$(adb_cmd shell dumpsys thermalservice | tr -d '\r')" >"$dir/thermalservice.txt"
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

run_round() {
  local round="$1"
  local deadline line
  echo "## round=$round uid=$package_uid usb_powered=false"
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

  capture_round "$round"
  line="$(app_read "$RUST_CONTROL_LOG")"
  if ! printf '%s\n' "$line" | rg -q '^result=pass rc=0$'; then
    echo "round=$round FAIL: Rust control result"
    failures=$((failures + 1))
    return 0
  fi
  if ! printf '%s\n' "$line" | rg -q "^abi_version=1 uid=$package_uid .* rounds=1$"; then
    echo "round=$round FAIL: Rust uid/ABI identity"
    failures=$((failures + 1))
    return 0
  fi
  if ! printf '%s\n' "$line" | rg -q "^status_set .*owner_cache=1 block_uid_set=1 block_uid=$package_uid "; then
    echo "round=$round FAIL: Rust typed policy set"
    failures=$((failures + 1))
    return 0
  fi
  if ! printf '%s\n' "$line" | rg -q '^status_after .*owner_cache=0 block_uid_set=0 '; then
    echo "round=$round FAIL: Rust typed policy clear"
    failures=$((failures + 1))
    return 0
  fi
  echo "round=$round PASS: Rust typed status/policy set/rollback completed as app uid"
}

cleanup() {
  stop_app || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    echo "battery_reset=done"
    battery_unplugged=0
  fi
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r' \
    >"$RESULT_DIR/processes-after-cleanup.txt" || true
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

echo "# SAKAMOTO-9 Android Rust FFI packaged VAPI control POC"
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

adb_cmd logcat -c
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez start true --es mode vpp --ez enableIpv6 true >/dev/null
sleep "$WARMUP_SECONDS"
if ! wait_for_api_socket; then
  echo "FAIL: app-private VPP API socket did not appear" >&2
  app_cmd cat files/vpp/runtime/startup.conf >"$RESULT_DIR/startup.conf" 2>/dev/null || true
  app_read files/vpp/logs/vpp-stdout.log >"$RESULT_DIR/vpp-stdout.log"
  exit 1
fi
echo "api_socket=ready"
app_cmd cat files/vpp/runtime/startup.conf >"$RESULT_DIR/startup.conf"
app_cmd cat files/vpp/logs/vpp-stdout.log >"$RESULT_DIR/vpp-stdout.log" 2>/dev/null || true

for round in $(seq 1 "$ROUNDS"); do
  run_round "$round"
done

app_read files/vpp/logs/vpp-cli.log >"$RESULT_DIR/vpp-cli.log" 2>/dev/null || true
adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' >"$RESULT_DIR/final-logcat.txt"
adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r' >"$RESULT_DIR/processes-before-cleanup.txt"
adb_cmd shell dumpsys battery | tr -d '\r' >"$RESULT_DIR/battery-before-reset.txt"
adb_cmd shell dumpsys thermalservice | tr -d '\r' >"$RESULT_DIR/thermal-after.txt"

cleanup
if ! grep -Eq 'USB powered: true|USB powered=true' "$RESULT_DIR/battery-after-reset.txt"; then
  echo "cleanup FAIL: USB power override was not reset" >&2
  failures=$((failures + 1))
fi

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-9 Rust FFI packaged VAPI control failures=$failures" >&2
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-9 Rust FFI packaged VAPI control rounds=$ROUNDS"
echo "result_dir=$RESULT_DIR"
