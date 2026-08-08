#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb="$repo_root/dev/adb"
package="com.sakamoto.snort.androidruntime"
activity="$package/.DebugControlActivity"
apk="$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk"
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
    echo "BLOCKED: specify --serial when ./dev/adb sees multiple/no devices" >&2
    exit 77
  fi
  target_serial="${devices[0]}"
else
  target_state="$("$adb" -s "$target_serial" get-state 2>/dev/null | tr -d '\r\n' || true)"
  if [[ "$target_state" != "device" ]]; then
    echo "BLOCKED: Android device is unavailable: $target_serial" >&2
    exit 77
  fi
fi

adb_cmd() { "$adb" -s "$target_serial" "$@"; }

"$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
adb_cmd install -r "$apk" >/dev/null
adb_cmd shell pm grant "$package" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$package"

evidence_file="${ANDROID_RUNTIME_EVIDENCE_FILE:-/tmp/sakamoto-67-android-runtime-${target_serial}.log}"
{
  echo "serial=$target_serial"
  echo "package=$package"
  echo "apk=$apk"
  echo "start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$evidence_file"

cleanup() {
  adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
}
trap cleanup EXIT

adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile root >/dev/null
running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^protocol=vpp-runtime-health/v1$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state"; then
    running=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "runtime start failed; raw state evidence: $evidence_file.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$running" == 1 ]] || { echo "runtime did not reach running; evidence=$evidence_file.state" >&2; exit 1; }

# Closing/recreating the Activity must not alter the service-owned runtime.
adb_cmd shell input keyevent KEYCODE_HOME
adb_cmd shell am start -n "$activity" >/dev/null
sleep 1
state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"

pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
[[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || { echo "running snapshot has no PID" >&2; exit 1; }
adb_cmd shell "kill -KILL $pid" || true
for _ in $(seq 1 20); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^mayBeActive=false$' <<<"$state"; then
    break
  fi
  sleep 1
done

adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null
for _ in $(seq 1 20); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    break
  fi
  sleep 1
done
grep -q '^state=stopped$' <<<"$state"
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp \
  && test ! -e files/profiles/root/vpp/runtime/cli.sock \
  && test ! -e files/profiles/root/vpp/runtime/statseg.sock \
  && test ! -e files/profiles/root/vpp/shm'"
if adb_cmd shell ps -A -o NAME,args | tr -d '\r' | grep -q 'libvpp_runtime.so'; then
  echo "VPP process residue remains after stop" >&2
  exit 1
fi

echo "android runtime incubator lifecycle: PASS"
echo "evidence=$evidence_file"
