#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb="$repo_root/dev/adb"
package="com.sakamoto.snort.vpnlite"
activity="$package/.MainActivity"
apk="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/sakamoto-runtime-debug.apk"
state_path="files/runtime-state/snapshot.properties"
target_serial="${ADB_SERIAL:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--serial requires a device serial" >&2; exit 2; }
      target_serial="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$target_serial" ]]; then
  mapfile -t devices < <("$adb" devices | tr -d '\r' | awk '$2 == "device" {print $1}')
  if [[ "${#devices[@]}" != 1 ]]; then
    echo "BLOCKED: specify --serial when ./dev/adb sees multiple devices" >&2
    exit 77
  fi
  target_serial="${devices[0]}"
else
  target_state="$("$adb" -s "$target_serial" get-state 2>/dev/null | tr -d '\r\n' || true)"
  if [[ "$target_state" != "device" ]]; then
    echo "BLOCKED: requested Android device is unavailable: $target_serial" >&2
    exit 77
  fi
fi

adb_cmd() {
  "$adb" -s "$target_serial" "$@"
}

bash "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh"

stop_runtime() {
  adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
}
trap stop_runtime EXIT

adb_cmd install -r "$apk" >/dev/null
adb_cmd shell pm grant "$package" android.permission.POST_NOTIFICATIONS
adb_cmd shell am force-stop "$package"
adb_cmd shell am start -n "$activity" --ez runtimeStart true >/dev/null
adb_cmd shell am start -n "$activity" --ez runtimeStart true >/dev/null

running=0
for _ in $(seq 1 24); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^protocol=vpp-runtime-health/v1$' <<<"$state" \
      && grep -q '^abi=arm64-v8a$' <<<"$state" \
      && grep -q '^abiEvidence=manifest-arm64-v8a,device-arm64-v8a$' <<<"$state" \
      && grep -q '^mayBeActive=true$' <<<"$state" \
      && grep -q '^version=v' <<<"$state"; then
    running=1
    break
  fi
  sleep 1
done
[[ "$running" == 1 ]] || { echo "runtime did not reach running" >&2; exit 1; }

owner_token="$(adb_cmd shell run-as "$package" cat files/profiles/root/vpp/runtime/owner.token \
  2>/dev/null | tr -d '\r\n' || true)"
[[ "$owner_token" =~ ^[0-9a-fA-F-]{36}$ ]] || {
  echo "runtime owner token was not durably persisted" >&2
  exit 1
}

process_dump="$(adb_cmd shell ps -A -o PID,NAME,args | tr -d '\r')"
runtime_count="$(grep -c 'libvpp_runtime.so' <<<"$process_dump" || true)"
[[ "$runtime_count" == 1 ]] || {
  echo "duplicate start produced $runtime_count VPP runtimes" >&2
  exit 1
}

fgs_dump="$(adb_cmd shell dumpsys activity services "$package")"
grep -q 'startForegroundCount=1' <<<"$fgs_dump"
notification_dump="$(adb_cmd shell dumpsys notification --noredact)"
grep -q 'Protection running' <<<"$notification_dump"

# Home and reopen exercise Activity/WebView projection without stopping the service.
adb_cmd shell input keyevent KEYCODE_HOME
adb_cmd shell am start -n "$activity" >/dev/null
state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"

stop_runtime
stopped=0
for _ in $(seq 1 20); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    stopped=1
    break
  fi
  sleep 1
done
[[ "$stopped" == 1 ]] || { echo "runtime did not reach verified stopped" >&2; exit 1; }

process_dump="$(adb_cmd shell ps -A -o NAME,args)"
if grep -q 'libvpp_runtime.so' <<<"$process_dump"; then
  echo "VPP process survived clean stop" >&2
  exit 1
fi

adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp \
  && test ! -e files/profiles/root/vpp/runtime/cli.sock \
  && test ! -e files/profiles/root/vpp/runtime/statseg.sock \
  && test ! -e files/profiles/root/vpp/shm'"

echo "android runtime lifecycle: PASS"
