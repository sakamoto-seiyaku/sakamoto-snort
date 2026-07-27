#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb="$repo_root/dev/adb"
package="com.sakamoto.snort.vpnlite"
activity="$package/.MainActivity"
apk="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/sakamoto-runtime-debug.apk"
state_path="files/runtime-state/snapshot.properties"

if [[ ! -f "$apk" ]]; then
  bash "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh"
fi

device_count="$($adb devices | tr -d '\r' | awk '$2 == "device" {count++} END {print count + 0}')"
if [[ "$device_count" != "1" ]]; then
  echo "BLOCKED: expected one Android device through ./dev/adb, found $device_count" >&2
  exit 77
fi

stop_runtime() {
  "$adb" shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
  sleep 2
}
trap stop_runtime EXIT

"$adb" install -r "$apk" >/dev/null
"$adb" shell pm grant "$package" android.permission.POST_NOTIFICATIONS
"$adb" shell am force-stop "$package"
"$adb" shell am start -n "$activity" --ez runtimeStart true >/dev/null

running=0
for _ in $(seq 1 24); do
  state="$($adb shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^abi=arm64-v8a$' <<<"$state" \
      && grep -q '^version=v' <<<"$state"; then
    running=1
    break
  fi
  sleep 1
done
[[ "$running" == 1 ]] || { echo "runtime did not reach running" >&2; exit 1; }

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
state="$($adb shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=stopped$' <<<"$state"
process_dump="$($adb shell ps -A -o NAME,args)"
if grep -q 'libvpp_runtime.so' <<<"$process_dump"; then
  echo "VPP process survived clean stop" >&2
  exit 1
fi

echo "android runtime lifecycle: PASS"
