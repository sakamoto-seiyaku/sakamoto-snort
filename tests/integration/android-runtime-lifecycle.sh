#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb="$repo_root/dev/adb"
package="com.sakamoto.snort.vpnlite"
activity="$package/.MainActivity"
apk="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/sakamoto-runtime-debug.apk"
state_path="files/runtime-state/snapshot.properties"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

bash "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh"

device_count="$($adb devices | tr -d '\r' | awk '$2 == "device" {count++} END {print count + 0}')"
if [[ "$device_count" != "1" ]]; then
  echo "BLOCKED: expected one Android device through ./dev/adb, found $device_count" >&2
  exit 77
fi

stop_runtime() {
  "$adb" shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 1
}
trap stop_runtime EXIT

"$adb" install -r "$apk" >/dev/null
"$adb" shell pm grant "$package" android.permission.POST_NOTIFICATIONS
"$adb" shell am force-stop "$package"
"$adb" shell am start -n "$activity" --ez runtimeStart true >/dev/null
"$adb" shell am start -n "$activity" --ez runtimeStart true >/dev/null

running=0
for _ in $(seq 1 24); do
  state="$($adb shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
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

process_dump="$($adb shell ps -A -o PID,NAME,args | tr -d '\r')"
runtime_count="$(grep -c 'libvpp_runtime.so' <<<"$process_dump" || true)"
[[ "$runtime_count" == 1 ]] || {
  echo "duplicate start produced $runtime_count VPP runtimes" >&2
  exit 1
}

fgs_dump="$($adb shell dumpsys activity services "$package")"
grep -q 'startForegroundCount=1' <<<"$fgs_dump"
notification_dump="$($adb shell dumpsys notification --noredact)"
grep -q 'Protection running' <<<"$notification_dump"

# Home and reopen exercise Activity/WebView projection without stopping the service.
"$adb" shell input keyevent KEYCODE_HOME
"$adb" shell am start -n "$activity" >/dev/null
state="$($adb shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"

stop_runtime
stopped=0
for _ in $(seq 1 20); do
  state="$($adb shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    stopped=1
    break
  fi
  sleep 1
done
[[ "$stopped" == 1 ]] || { echo "runtime did not reach verified stopped" >&2; exit 1; }

process_dump="$($adb shell ps -A -o NAME,args)"
if grep -q 'libvpp_runtime.so' <<<"$process_dump"; then
  echo "VPP process survived clean stop" >&2
  exit 1
fi

"$adb" shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp \
  && test ! -e files/profiles/root/vpp/runtime/cli.sock \
  && test ! -e files/profiles/root/vpp/runtime/statseg.sock \
  && test ! -e files/profiles/root/vpp/shm'"

echo "android runtime lifecycle: PASS"
