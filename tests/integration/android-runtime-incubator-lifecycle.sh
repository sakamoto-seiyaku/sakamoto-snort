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
# The harness owns this debug package's data and starts from a clean durable
# projection; all crash/recreation/replacement assertions happen within this
# invocation. Clearing here also removes residue from an interrupted run.
adb_cmd shell pm clear "$package" >/dev/null
# pm clear invokes the old isolated service's asynchronous onDestroy. Drain
# that callback before the second clear so it cannot recreate profile residue.
adb_cmd shell am force-stop "$package"
for _ in $(seq 1 20); do
  stale_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' \
    | tr -d '\r' | awk -v app="$package" '$2 == app || $2 == app ":runtime"')"
  [[ -z "$stale_processes" ]] && break
  sleep 1
done
[[ -z "$stale_processes" ]] \
  || { echo "BLOCKED: package processes did not drain after clear" >&2; exit 77; }
adb_cmd shell pm clear "$package" >/dev/null
notification_granted=0
for _ in $(seq 1 20); do
  adb_cmd shell pm grant "$package" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
  permission_line="$(adb_cmd shell dumpsys package "$package" 2>/dev/null \
    | tr -d '\r' | awk '/POST_NOTIFICATIONS: granted=/{print; found=1} END {if (!found) print ""}')"
  if [[ "$permission_line" == *"granted=true"* ]]; then
    notification_granted=1
    break
  fi
  sleep 1
done
[[ "$notification_granted" == 1 ]] \
  || { echo "BLOCKED: notification permission could not be granted" >&2; exit 77; }
adb_cmd shell am force-stop "$package"
# Package replacement/force-stop can invoke the old isolated service's
# asynchronous onDestroy while the new Activity is already launching. Wait
# for both package processes to leave before issuing the first start request,
# otherwise the old cleanup callback can overwrite the new durable snapshot.
for _ in $(seq 1 20); do
  stale_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' \
    | tr -d '\r' | awk -v app="$package" '$2 == app || $2 == app ":runtime"')"
  [[ -z "$stale_processes" ]] && break
  sleep 1
done
if [[ -n "$stale_processes" ]]; then
  echo "BLOCKED: package processes did not drain after force-stop" >&2
  exit 77
fi
app_uid="$(adb_cmd shell run-as "$package" id -u | tr -d '\r\n')"
[[ "$app_uid" =~ ^[0-9]+$ ]] || { echo "unable to resolve app UID" >&2; exit 1; }

evidence_file="${ANDROID_RUNTIME_EVIDENCE_FILE:-/tmp/sakamoto-67-android-runtime-${target_serial}.log}"
{
  echo "serial=$target_serial"
  echo "package=$package"
  echo "apk=$apk"
  echo "start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$evidence_file"
rtk unzip -p "$apk" assets/vpp-runtime-provenance.properties \
  >"$evidence_file.provenance"
{
  echo "provenance=$evidence_file.provenance"
  echo "validity=raw device lifecycle evidence; see per-step state/process files"
  echo "residue_checks=profile trees and final process list"
} >>"$evidence_file"

cleanup() {
  adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    remaining="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' 2>/dev/null \
      | tr -d '\r' | awk -v app="$package" '$2 == app || $2 == app ":runtime"')"
    [[ -z "$remaining" ]] && break
    sleep 1
  done
}
trap cleanup EXIT

adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile root >/dev/null
running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^coreHealth=ok$' <<<"$state" \
      && grep -q '^adapterReadiness=unavailable$' <<<"$state" \
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

# The Activity and RuntimeService have separate Android process identities.
# Kill only the exact Activity PID after validating its package/UID; the
# foreground :runtime process and VPP owner must survive recreation.
adb_cmd shell input keyevent KEYCODE_HOME
process_snapshot="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r')"
activity_pid="$(awk -v expected="$package" '$2 == expected {print $1; exit}' <<<"$process_snapshot")"
service_process_name="$package:runtime"
service_pid="$(awk -v expected="$service_process_name" '$2 == expected {print $1; exit}' <<<"$process_snapshot")"
[[ "$activity_pid" =~ ^[0-9]+$ && "$activity_pid" != 0 ]] \
  || { echo "unable to resolve exact Activity PID" >&2; exit 1; }
[[ "$service_pid" =~ ^[0-9]+$ && "$service_pid" != 0 && "$service_pid" != "$activity_pid" ]] \
  || { echo "RuntimeService is not isolated as $service_process_name" >&2; exit 1; }
activity_uid="$(adb_cmd shell su 0 sh -c "grep ^Uid: /proc/$activity_pid/status" \
  | tr -d '\r' | awk '{print $2}')"
service_uid="$(adb_cmd shell su 0 sh -c "grep ^Uid: /proc/$service_pid/status" \
  | tr -d '\r' | awk '{print $2}')"
[[ "$activity_uid" == "$app_uid" && "$service_uid" == "$app_uid" ]] \
  || { echo "Activity/service process UID identity mismatch" >&2; exit 1; }
activity_cmdline="$(adb_cmd shell su 0 sh -c "tr -d '\0' </proc/$activity_pid/cmdline" \
  | tr -d '\r')"
service_cmdline="$(adb_cmd shell su 0 sh -c "tr -d '\0' </proc/$service_pid/cmdline" \
  | tr -d '\r')"
grep -Fq "$package" <<<"$activity_cmdline"
grep -Fq "$package:runtime" <<<"$service_cmdline"

state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"
pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
generation="$(awk -F= '$1 == "generation" {print $2}' <<<"$state")"
[[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || { echo "running snapshot has no PID" >&2; exit 1; }
root_uid="$(adb_cmd shell "su 0 sh -c 'grep ^Uid: /proc/$pid/status'" \
  | tr -d '\r' | awk '{print $2}')"
[[ "$root_uid" == 0 ]] || { echo "root profile VPP UID was $root_uid" >&2; exit 1; }

kill_evidence="$evidence_file.activity-kill"
if ! kill_output="$(adb_cmd shell su 0 sh -c "kill -KILL $activity_pid" 2>&1)"; then
  printf 'pid=%s\nname=%s\ncommand=su 0 sh -c '\''kill -KILL %s'\''\n%s\n' \
    "$activity_pid" "$package" "$activity_pid" "$kill_output" >"$kill_evidence"
  echo "unable to kill validated Activity PID; evidence=$kill_evidence" >&2
  exit 1
fi
printf 'pid=%s\nname=%s\nuid=%s\nservicePid=%s\nserviceName=%s\ncommand=su 0 sh -c '\''kill -KILL %s'\''\n%s\n' \
  "$activity_pid" "$package" "$activity_uid" "$service_pid" "$service_process_name" \
  "$activity_pid" "$kill_output" >"$kill_evidence"
for _ in $(seq 1 10); do
  if ! adb_cmd shell "su 0 sh -c 'kill -0 $activity_pid'" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if adb_cmd shell "su 0 sh -c 'kill -0 $activity_pid'" >/dev/null 2>&1; then
  echo "validated Activity PID remained alive after kill; evidence=$kill_evidence" >&2
  exit 1
fi
if ! adb_cmd shell "su 0 sh -c 'kill -0 $service_pid'" >/dev/null 2>&1; then
  echo "isolated RuntimeService process died with Activity; evidence=$kill_evidence" >&2
  exit 1
fi
adb_cmd shell am start -n "$activity" >/dev/null
sleep 1
state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"
recreated_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
recreated_generation="$(awk -F= '$1 == "generation" {print $2}' <<<"$state")"
[[ "$recreated_pid" == "$pid" && "$recreated_generation" == "$generation" ]] \
  || { echo "Activity recreation changed runtime PID/generation" >&2; exit 1; }
adb_cmd shell run-as "$package" cat files/logs/runtime-service.log \
  | tr -d '\r' >"$evidence_file.query.log"
grep -q 'core_control rc=' "$evidence_file.query.log" \
  || { echo "active query did not leave generated-VAPI evidence" >&2; exit 1; }

kill_evidence="$evidence_file.crash-kill"
if ! kill_output="$(adb_cmd shell "su 0 sh -c 'kill -KILL $pid'" 2>&1)"; then
  printf 'pid=%s\ncommand=su 0 sh -c '\''kill -KILL %s'\''\n%s\n' \
    "$pid" "$pid" "$kill_output" >"$kill_evidence"
  echo "unable to kill validated VPP PID as root; evidence=$kill_evidence" >&2
  exit 1
fi
printf 'pid=%s\ncommand=su 0 sh -c '\''kill -KILL %s'\''\n%s\n' \
  "$pid" "$pid" "$kill_output" >"$kill_evidence"
crash_recovered=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null \
    | tr -d '\r' || true)"
  process_snapshot="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' 2>/dev/null \
    | tr -d '\r' || true)"
  process_alive=0
  if adb_cmd shell "su 0 sh -c 'kill -0 $pid'" >/dev/null 2>&1; then
    process_alive=1
  fi
  process_present=0
  if awk -v expected_pid="$pid" '$1 == expected_pid { found = 1 } END { exit found ? 0 : 1 }' \
      <<<"$process_snapshot"; then
    process_present=1
  fi
  {
    echo "process_alive=$process_alive"
    echo "process_present=$process_present"
    echo "$state"
    echo "$process_snapshot"
  } >"$evidence_file.crash.state"
  if [[ "$process_alive" == 0 ]] \
      && [[ "$process_present" == 0 ]] \
      && grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^errorCode=unexpected_exit$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    crash_recovered=1
    break
  fi
  sleep 1
done
[[ "$crash_recovered" == 1 ]] \
  || { echo "runtime crash was not recovered with durable unexpected_exit; evidence=$evidence_file.crash.state" >&2; exit 1; }
if ! adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp \
  && test ! -e files/profiles/root/vpp/runtime/cli.sock \
  && test ! -e files/profiles/root/vpp/runtime/statseg.sock \
  && test ! -e files/profiles/root/vpp/shm'"; then
  echo "profile residue remains after crash recovery; evidence=$evidence_file.crash.state" >&2
  exit 1
fi

# Prove the bounded orphan-recovery seam independently of the normal exit
# monitor. Kill the VPP owner and both Android processes without giving the
# service a cleanup turn, then remove the durable PID fields while preserving
# root-owned profile residue. A fresh QUERY must audit /proc ownership before
# it is allowed to remove that residue.
adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile root >/dev/null
orphan_running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.orphan-running.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state"; then
    orphan_running=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "orphan setup failed; evidence=$evidence_file.orphan-running.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$orphan_running" == 1 ]] \
  || { echo "orphan setup did not reach running; evidence=$evidence_file.orphan-running.state" >&2; exit 1; }
orphan_vpp_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
orphan_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r')"
orphan_service_pid="$(awk -v expected="$package:runtime" '$2 == expected {print $1; exit}' <<<"$orphan_processes")"
orphan_activity_pid="$(awk -v expected="$package" '$2 == expected {print $1; exit}' <<<"$orphan_processes")"
[[ "$orphan_vpp_pid" =~ ^[0-9]+$ && "$orphan_vpp_pid" != 0 \
    && "$orphan_service_pid" =~ ^[0-9]+$ && "$orphan_activity_pid" =~ ^[0-9]+$ ]] \
  || { echo "unable to resolve orphan test PIDs" >&2; exit 1; }
orphan_before="$(adb_cmd shell su 0 sh -c "ls -ln /data/user/0/$package/files/profiles/root/vpp/runtime/owner.token /data/user/0/$package/files/profiles/root/vpp/startup.conf 2>&1" | tr -d '\r')"
printf 'vppPid=%s\nservicePid=%s\nactivityPid=%s\n%s\n' \
  "$orphan_vpp_pid" "$orphan_service_pid" "$orphan_activity_pid" "$orphan_before" \
  >"$evidence_file.orphan-before"
adb_cmd shell su 0 sh -c "kill -KILL $orphan_vpp_pid; kill -KILL $orphan_service_pid; kill -KILL $orphan_activity_pid" >/dev/null
for _ in $(seq 1 20); do
  orphan_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' 2>/dev/null | tr -d '\r' || true)"
  if ! awk -v pid="$orphan_vpp_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes" \
      && ! awk -v pid="$orphan_service_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes"; then
    break
  fi
  sleep 1
done
if awk -v pid="$orphan_vpp_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes"; then
  echo "orphan VPP owner did not exit; evidence=$evidence_file.orphan-before" >&2
  exit 1
fi
adb_cmd shell su 0 sh -c "rm -f /data/user/0/$package/files/profiles/root/vpp/runtime/vpp.pid" >/dev/null
adb_cmd shell run-as "$package" sed -i 's/^pid=.*/pid=-1/' "$state_path"
orphan_after="$(adb_cmd shell su 0 sh -c "find /data/user/0/$package/files/profiles/root/vpp -maxdepth 3 -printf '%u %g %p\\n' 2>/dev/null | sort" | tr -d '\r')"
printf 'state_pid=-1\n%s\n' "$orphan_after" >"$evidence_file.orphan-residue"
grep -q 'owner.token' <<<"$orphan_after"
grep -q 'startup.conf' <<<"$orphan_after"

adb_cmd shell am start -n "$activity" >/dev/null
orphan_recovered=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.orphan-recovery.state"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^errorCode=runtime_recovered$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    orphan_recovered=1
    break
  fi
  sleep 1
done
[[ "$orphan_recovered" == 1 ]] \
  || { echo "orphan residue was not recovered; evidence=$evidence_file.orphan-recovery.state" >&2; exit 1; }
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp'" >/dev/null
adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r' >"$evidence_file.orphan-final.ps"
if grep -q 'libvpp_runtime.so' "$evidence_file.orphan-final.ps"; then
  echo "VPP process appeared during orphan recovery; evidence=$evidence_file.orphan-final.ps" >&2
  exit 1
fi

# A recovered service must be able to start the same profile again before the
# final clean stop. This catches a one-shot cleanup pass that only reports an
# inactive state but leaves the lifecycle owner unusable.
adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile root >/dev/null
restart_running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.restart.state"
    if grep -q '^state=running$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^coreHealth=ok$' <<<"$state" \
      && grep -q '^adapterReadiness=unavailable$' <<<"$state" \
      && grep -q '^protocol=vpp-runtime-health/v1$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state"; then
    restart_running=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "runtime restart failed; raw state evidence: $evidence_file.restart.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$restart_running" == 1 ]] \
  || { echo "runtime did not recover after crash; evidence=$evidence_file.restart.state" >&2; exit 1; }

# A controlled debug seam must make cleanup fail closed: replacement is not
# launched, and the old root PID/UID remains the sole owner until the seam is
# cleared. The seam is app-scoped and never targets an arbitrary PID.
root_before_fault="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
root_fault_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$root_before_fault")"
root_fault_generation="$(awk -F= '$1 == "generation" {print $2}' <<<"$root_before_fault")"
adb_cmd shell am start -n "$activity" --ez runtimeCleanupFault true \
  --ez runtimeStart true --es runtimeProfile vpn >/dev/null
fault_blocked=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null \
    | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.cleanup-fault.state"
  if grep -q '^state=error$' <<<"$state" \
      && grep -q '^errorCode=cleanup_failed$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state" \
      && grep -q '^mayBeActive=true$' <<<"$state" \
      && [[ "$(awk -F= '$1 == "pid" {print $2}' <<<"$state")" == "$root_fault_pid" ]]; then
    fault_blocked=1
    break
  fi
  sleep 1
done
[[ "$fault_blocked" == 1 ]] \
  || { echo "cleanup fault did not block replacement; evidence=$evidence_file.cleanup-fault.state" >&2; exit 1; }
if ! adb_cmd shell "su 0 sh -c 'kill -0 $root_fault_pid'" >/dev/null 2>&1; then
  echo "root owner died during injected cleanup failure" >&2
  exit 1
fi
root_fault_uid="$(adb_cmd shell "su 0 sh -c 'grep ^Uid: /proc/$root_fault_pid/status'" \
  | tr -d '\r' | awk '{print $2}')"
[[ "$root_fault_uid" == 0 ]] || { echo "cleanup-fault root owner UID changed" >&2; exit 1; }
if adb_cmd shell "run-as $package sh -c 'test -e files/profiles/vpn/vpp'" >/dev/null 2>&1; then
  echo "VPN profile residue was created during blocked replacement" >&2
  exit 1
fi
printf 'rootPid=%s\nrootGeneration=%s\nrootUid=%s\n' \
  "$root_fault_pid" "$root_fault_generation" "$root_fault_uid" \
  >>"$evidence_file.cleanup-fault.state"

# Clear only the injected debug state, then prove normal recovery and the
# successful root -> app-UID VPN replacement.
adb_cmd shell am start -n "$activity" --ez runtimeCleanupFault false >/dev/null
adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile vpn >/dev/null

# Replace the root profile with the app-UID VPN core profile. This is a
# lifecycle-only proof in SAKAMOTO-67; no TUN fd or packet Adapter is claimed.
vpn_running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null \
    | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.vpn.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^profile=vpn$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && grep -q '^coreHealth=ok$' <<<"$state" \
      && grep -q '^adapterReadiness=unavailable$' <<<"$state"; then
    vpn_running=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "VPN core start failed; evidence=$evidence_file.vpn.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$vpn_running" == 1 ]] \
  || { echo "VPN core did not reach running; evidence=$evidence_file.vpn.state" >&2; exit 1; }
vpn_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
vpn_uid="$(adb_cmd shell "su 0 sh -c 'grep ^Uid: /proc/$vpn_pid/status'" \
  | tr -d '\r' | awk '{print $2}')"
[[ "$vpn_uid" == "$app_uid" ]] \
  || { echo "VPN profile VPP UID was $vpn_uid, expected app UID $app_uid" >&2; exit 1; }
adb_cmd shell input keyevent KEYCODE_HOME
adb_cmd shell am start -n "$activity" >/dev/null
sleep 1
state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"
grep -q '^profile=vpn$' <<<"$state"

adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null
for _ in $(seq 1 20); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.final.state"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    break
  fi
  sleep 1
done
grep -q '^state=stopped$' <<<"$state"
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp \
  && test ! -e files/profiles/vpn/vpp \
  && test ! -e files/profiles/root/vpp/runtime/cli.sock \
  && test ! -e files/profiles/root/vpp/runtime/statseg.sock \
  && test ! -e files/profiles/root/vpp/shm'"
final_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r' || true)"
printf '%s\n' "$final_processes" >"$evidence_file.final.ps"
if grep -q 'libvpp_runtime.so' <<<"$final_processes"; then
  echo "VPP process residue remains after stop" >&2
  exit 1
fi

echo "android runtime incubator lifecycle: PASS"
echo "evidence=$evidence_file"
