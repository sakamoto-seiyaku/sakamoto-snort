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
apk_sha256="$(sha256sum "$apk" | awk '{print $1}')"
runtime_sha256="$(rtk unzip -p "$apk" lib/arm64-v8a/libvpp_runtime.so \
  | sha256sum | awk '{print $1}')"
[[ "$apk_sha256" =~ ^[0-9a-fA-F]{64}$ && "$runtime_sha256" =~ ^[0-9a-fA-F]{64}$ ]] \
  || { echo "unable to bind APK/runtime SHA-256 evidence" >&2; exit 1; }
adb_cmd install -r "$apk" >/dev/null
app_uid="$(adb_cmd shell run-as "$package" id -u | tr -d '\r\n')"
[[ "$app_uid" =~ ^[0-9]+$ ]] || { echo "unable to resolve app UID" >&2; exit 1; }
installed_apk_path="$(adb_cmd shell pm path "$package" | tr -d '\r' \
  | sed -n 's/^package://p' | head -n 1)"
expected_runtime_path="${installed_apk_path%/base.apk}/lib/arm64/libvpp_runtime.so"
[[ "$expected_runtime_path" == */lib/arm64/libvpp_runtime.so ]] \
  || { echo "unable to resolve installed packaged runtime path" >&2; exit 1; }

evidence_file="${ANDROID_RUNTIME_EVIDENCE_FILE:-/tmp/sakamoto-67-android-runtime-${target_serial}.log}"
app_head_commit="$(git -C "$repo_root" rev-parse HEAD)"
{
  echo "serial=$target_serial"
  echo "package=$package"
  echo "apk=$apk"
  echo "apkSha256=$apk_sha256"
  echo "runtimeSha256=$runtime_sha256"
  echo "installedRuntimePath=$expected_runtime_path"
  echo "appHeadCommit=$app_head_commit"
  echo "start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$evidence_file"
rtk unzip -p "$apk" assets/vpp-runtime-provenance.properties \
  >"$evidence_file.provenance"
{
  echo "provenance=$evidence_file.provenance"
  echo "validity=raw device lifecycle evidence; see per-step state/process files"
  echo "residue_checks=verified VPP owners, profile trees, sockets, shm, and final process list"
} >>"$evidence_file"

verified_owner_snapshot() {
  local remote_script
  remote_script="$(cat <<EOF
app_data=/data/user/0/$package
expected_app_uid=$app_uid
expected_exe=$expected_runtime_path
proc_reader='runcon u:r:ksu:s0 '
ps -A -o PID,UID,args | while read -r pid ps_uid args; do
  case "\$args" in *libvpp_runtime.so*) ;; *) continue ;; esac
  [ -d "/proc/\$pid" ] || continue
  proc_uid=\$(\$proc_reader awk '\$1 == "Uid:" {print \$2; exit}' "/proc/\$pid/status" 2>/dev/null) || continue
  [ "\$proc_uid" = "0" ] || [ "\$proc_uid" = "\$expected_app_uid" ] || continue
  exe=\$(\$proc_reader readlink "/proc/\$pid/exe" 2>/dev/null) || continue
  # The installed package path is immutable and was bound to runtimeSha256
  # above. /proc/<pid>/exe content can become unreadable after VPP drops its
  # dumpability, so exact path identity is the strong packaged-owner proof.
  [ "\$exe" = "\$expected_exe" ] || continue
  for profile in root vpn; do
    profile_uid="\$expected_app_uid"
    [ "\$profile" = root ] && profile_uid=0
    profile_dir="\$app_data/files/profiles/\$profile/vpp"
    runtime_dir="\$profile_dir/runtime"
    startup="\$profile_dir/startup.conf"
    token_file="\$runtime_dir/owner.token"
    [ -f "\$startup" ] && [ -f "\$token_file" ] || continue
    [ "\$proc_uid" = "\$profile_uid" ] || continue
    grep -Fq "runtime-dir \$runtime_dir" "\$startup" 2>/dev/null || continue
    grep -Fq "cli-listen \$runtime_dir/cli.sock" "\$startup" 2>/dev/null || continue
    grep -Fq "socket-name \$runtime_dir/api.sock" "\$startup" 2>/dev/null || continue
    grep -Fq "socket-name \$runtime_dir/statseg.sock" "\$startup" 2>/dev/null || continue
    token=\$(tr -d '[:space:]' <"\$token_file" 2>/dev/null) || continue
    echo "\$token" | grep -Eq '^[0-9A-Fa-f-]{36}$' || continue
    case "\$args" in *"\$startup"*) ;; *) continue ;; esac
    env=\$(runcon u:r:ksu:s0 sh -c "tr '\\0' '\\n' </proc/\$pid/environ 2>/dev/null" 2>/dev/null) || continue
    printf '%s\\n' "\$env" | grep -Fqx "SAKAMOTO_VPP_OWNER_TOKEN=\$token" || continue
    printf '%s\\n' "\$env" | grep -Fqx "SAKAMOTO_VPP_RUNTIME_DIR=\$runtime_dir" || continue
    printf '%s\\n' "\$env" | grep -Fqx "SAKAMOTO_RUNTIME_PROFILE=\$profile" || continue
    printf '%s\\t%s\\t%s\\t%s\\n' "\$profile" "\$pid" "\$proc_uid" "\$exe"
  done
done
EOF
  )"
  adb_cmd shell su 0 sh -c "$remote_script" | tr -d '\r' | awk 'NF'
}

all_vpp_process_snapshot() {
  adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' 2>/dev/null \
    | tr -d '\r' | awk '$2 == "libvpp_runtime.so"'
}

cleanup_verified_vpp_owners() {
  local phase="${1:-cleanup}"
  local owners pid profile owner_uid exe verified_after
  owners="$(verified_owner_snapshot || true)"
  printf 'phase=%s\n%s\n' "$phase" "$owners" >>"$evidence_file.owners" 2>/dev/null || true
  while IFS=$'\t' read -r profile pid owner_uid exe; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    adb_cmd shell su 0 sh -c "kill -TERM $pid" >/dev/null 2>&1 || true
  done <<<"$owners"
  for _ in $(seq 1 15); do
    verified_after="$(verified_owner_snapshot || true)"
    [[ -z "$verified_after" ]] && break
    sleep 1
  done
  verified_after="$(verified_owner_snapshot || true)"
  while IFS=$'\t' read -r profile pid owner_uid exe; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    # Re-read strong identity immediately before KILL. A reused PID or an
    # unreadable owner is never targeted by this cleanup helper.
    if awk -F '\t' -v p="$profile" -v id="$pid" \
        '$1 == p && $2 == id {found=1} END {exit found ? 0 : 1}' <<<"$verified_after"; then
      adb_cmd shell su 0 sh -c "kill -KILL $pid" >/dev/null 2>&1 || true
    fi
  done <<<"$verified_after"
  for _ in $(seq 1 15); do
    [[ -z "$(verified_owner_snapshot || true)" ]] && return 0
    sleep 1
  done
  verified_after="$(verified_owner_snapshot || true)"
  [[ -z "$verified_after" ]] || {
    echo "verified VPP owner did not stop during $phase; evidence=$evidence_file.owners" >&2
    return 1
  }
  # A remaining packaged VPP with unreadable/ambiguous identity is a block,
  # not permission to broaden the kill target.
  if [[ -n "$(all_vpp_process_snapshot || true)" ]]; then
    echo "unverified packaged VPP owner remains during $phase; refusing to kill" >&2
    return 1
  fi
}

assert_no_runtime_residue() {
  local residue residue_script
  # KernelSU's su parser drops an argument that begins with a newline, so the
  # privileged shell script must start with its first command byte.
  residue_script="app_data=/data/user/0/$package; for p in root vpn; do \
test ! -e \"\$app_data/files/profiles/\$p/vpp\" || exit 1; \
test ! -e \"\$app_data/files/profiles/\$p/vpp/runtime/cli.sock\" || exit 1; \
test ! -e \"\$app_data/files/profiles/\$p/vpp/runtime/api.sock\" || exit 1; \
test ! -e \"\$app_data/files/profiles/\$p/vpp/runtime/statseg.sock\" || exit 1; \
test ! -e \"\$app_data/files/profiles/\$p/vpp/shm\" || exit 1; \
done"
  residue="$(adb_cmd shell su 0 sh -c "$residue_script" 2>&1 | tr -d '\r' || true)"
  [[ -z "$residue" ]] || {
    echo "VPP/profile/socket/shm residue remains: $residue" >&2
    return 1
  }
  [[ -z "$(all_vpp_process_snapshot || true)" ]] || {
    echo "packaged VPP process residue remains" >&2
    return 1
  }
}

wait_package_drained() {
  local stale_processes=""
  for _ in $(seq 1 20); do
    stale_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' \
      | tr -d '\r' | awk -v app="$package" '$2 == app || $2 == app ":runtime"')"
    [[ -z "$stale_processes" ]] && return 0
    sleep 1
  done
  [[ -z "$stale_processes" ]]
}

assert_exactly_one_owner() {
  local expected_profile="$1" expected_pid="$2" owners all_vpp count
  owners="$(verified_owner_snapshot || true)"
  printf 'expectedProfile=%s\nexpectedPid=%s\n%s\n' \
    "$expected_profile" "$expected_pid" "$owners" >>"$evidence_file.exact-one"
  count="$(awk 'NF {n++} END {print n+0}' <<<"$owners")"
  [[ "$count" == 1 ]] || { echo "expected exactly one verified owner, got $count" >&2; return 1; }
  awk -F '\t' -v profile="$expected_profile" -v pid="$expected_pid" \
    'NF && $1 == profile && $2 == pid {found=1} END {exit found ? 0 : 1}' <<<"$owners" \
    || { echo "verified owner does not match $expected_profile/$expected_pid" >&2; return 1; }
  all_vpp="$(all_vpp_process_snapshot || true)"
  [[ "$(awk 'NF {n++} END {print n+0}' <<<"$all_vpp")" == 1 ]] \
    || { echo "global packaged VPP count is not exactly one" >&2; return 1; }
}

# Initial interrupted-run recovery: only strongly verified packaged owners
# may be signalled. Any ambiguous/unverified process blocks the gate.
cleanup_verified_vpp_owners initial-preclear
adb_cmd shell pm clear "$package" >/dev/null
adb_cmd shell am force-stop "$package"
wait_package_drained || { echo "BLOCKED: package processes did not drain after clear" >&2; exit 77; }
cleanup_verified_vpp_owners initial-postclear
assert_no_runtime_residue
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
if ! wait_package_drained; then
  echo "BLOCKED: package processes did not drain after force-stop" >&2
  exit 77
fi
cleanup_verified_vpp_owners initial-final
assert_no_runtime_residue

cleanup() {
  local exit_code=$?
  set +e
  adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null 2>&1 || true
  cleanup_verified_vpp_owners exit || true
  adb_cmd shell am force-stop "$package" >/dev/null 2>&1 || true
  wait_package_drained || true
  cleanup_verified_vpp_owners exit-post-force-stop || true
  if ! assert_no_runtime_residue; then
    echo "EXIT cleanup residue verification failed; evidence=$evidence_file" >&2
    [[ "$exit_code" == 0 ]] && exit_code=1
  fi
  exit "$exit_code"
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
activity_cmdline="$(adb_cmd shell su 0 sh -c "tr '\0' ' ' </proc/$activity_pid/cmdline" \
  | tr -d '\r')"
service_cmdline="$(adb_cmd shell su 0 sh -c "tr '\0' ' ' </proc/$service_pid/cmdline" \
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
root_round_pid="$pid"
assert_exactly_one_owner root "$root_round_pid"

# Capture the generated-VAPI query baseline before Activity recreation. A
# startup `core_control` line is not evidence that the later ACTION_QUERY ran.
query_baseline_log="$evidence_file.query-baseline.log"
adb_cmd shell run-as "$package" cat files/logs/runtime-service.log \
  | tr -d '\r' >"$query_baseline_log"
query_baseline_count="$(grep -c 'health_query=vapi_result .*generated_vapi=true' \
  "$query_baseline_log" || true)"

kill_evidence="$evidence_file.activity-kill"
if ! kill_output="$(adb_cmd shell "run-as $package kill -KILL $activity_pid" 2>&1)"; then
  printf 'pid=%s\nname=%s\ncommand=run-as %s kill -KILL %s\n%s\n' \
    "$activity_pid" "$package" "$package" "$activity_pid" "$kill_output" >"$kill_evidence"
  echo "unable to kill validated Activity PID; evidence=$kill_evidence" >&2
  exit 1
fi
printf 'pid=%s\nname=%s\nuid=%s\nservicePid=%s\nserviceName=%s\ncommand=run-as %s kill -KILL %s\n%s\n' \
  "$activity_pid" "$package" "$activity_uid" "$service_pid" "$service_process_name" \
  "$package" "$activity_pid" "$kill_output" >"$kill_evidence"
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
assert_exactly_one_owner root "$recreated_pid"
adb_cmd shell run-as "$package" cat files/logs/runtime-service.log \
  | tr -d '\r' >"$evidence_file.query.log"
query_after_count="$(grep -c 'health_query=vapi_result .*generated_vapi=true' \
  "$evidence_file.query.log" || true)"
[[ "$query_after_count" -gt "$query_baseline_count" ]] \
  || { echo "Activity recreation did not issue a new generated-VAPI query; evidence=$evidence_file.query.log" >&2; exit 1; }
query_revision="$(grep 'health_query=vapi_result .*generated_vapi=true' "$evidence_file.query.log" \
  | sed -n 's/.*revision=\([0-9][0-9]*\).*/\1/p' | tail -n 1)"
[[ "$query_revision" =~ ^[0-9]+$ ]] \
  || { echo "generated-VAPI query has no bounded revision; evidence=$evidence_file.query.log" >&2; exit 1; }
grep -q "health_query=vapi_start revision=$query_revision" "$evidence_file.query.log"
grep -q "health_query=result revision=$query_revision" "$evidence_file.query.log"

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
# monitor. Kill the Activity and isolated RuntimeService first, then force-stop
# the package to suppress its START_STICKY restart while the root VPP owner is
# still alive. A fresh manual Activity/service request must audit and adopt the
# same live owner rather than launching a second VPP.
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
assert_exactly_one_owner root "$orphan_vpp_pid"
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
# Exercise the durable-audit path rather than the valid projection fast path:
# remove only the durable PID and snapshot while the fully verified root VPP
# owner remains alive. The fresh service must recover the owner from its token,
# profile, executable, hash, UID, and runtime-directory evidence.
adb_cmd shell input keyevent KEYCODE_HOME
sleep 1
adb_cmd shell "run-as $package kill -KILL $orphan_activity_pid" >/dev/null
adb_cmd shell "run-as $package kill -KILL $orphan_service_pid" >/dev/null
adb_cmd shell am force-stop "$package" >/dev/null
for _ in $(seq 1 20); do
  orphan_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' 2>/dev/null | tr -d '\r' || true)"
  if awk -v pid="$orphan_vpp_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes" \
      && ! awk -v pid="$orphan_service_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes"; then
    break
  fi
  sleep 1
done
printf '%s\n' "$orphan_processes" >"$evidence_file.orphan-live.ps"
if ! awk -v pid="$orphan_vpp_pid" '$1 == pid {found=1} END {exit found ? 0 : 1}' <<<"$orphan_processes"; then
  echo "root VPP owner did not survive app-process death; evidence=$evidence_file.orphan-live.ps" >&2
  exit 1
fi

# Now that the app processes are gone, remove only the durable PID and
# projection while the verified root VPP owner remains alive. This forces the
# fresh service through PID-less token/profile/executable/hash/UID adoption.
adb_cmd shell su 0 sh -c "rm -f /data/user/0/$package/files/profiles/root/vpp/runtime/vpp.pid /data/user/0/$package/files/runtime-state/snapshot.properties"
orphan_pidless_files="$(adb_cmd shell su 0 sh -c "ls -ln /data/user/0/$package/files/profiles/root/vpp/runtime/owner.token /data/user/0/$package/files/profiles/root/vpp/startup.conf /data/user/0/$package/files/profiles/root/vpp/runtime/vpp.pid /data/user/0/$package/files/runtime-state/snapshot.properties 2>&1" | tr -d '\r' || true)"
printf '%s\n' "$orphan_pidless_files" >"$evidence_file.orphan-pidless"
if grep -q '/vpp.pid$' <<<"$orphan_pidless_files" \
    || grep -q '/snapshot.properties$' <<<"$orphan_pidless_files"; then
  echo "orphan PID/projection removal did not take effect; evidence=$evidence_file.orphan-pidless" >&2
  exit 1
fi

adb_cmd shell am start -n "$activity" >/dev/null
orphan_adopted=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.orphan-recovery.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state" \
      && [[ "$(awk -F= '$1 == "pid" {print $2}' <<<"$state")" == "$orphan_vpp_pid" ]]; then
    orphan_adopted=1
    break
  fi
  sleep 1
done
[[ "$orphan_adopted" == 1 ]] \
  || { echo "live orphan was not adopted with the same PID; evidence=$evidence_file.orphan-recovery.state" >&2; exit 1; }
assert_exactly_one_owner root "$orphan_vpp_pid"
printf 'adoptedPid=%s\n' "$orphan_vpp_pid" >>"$evidence_file.orphan-recovery.state"

# Once adoption is proven, a normal stop must clean the adopted owner and all
# profile residue without creating a replacement process.
adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null
orphan_stopped=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.orphan-stop.state"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    orphan_stopped=1
    break
  fi
  sleep 1
done
[[ "$orphan_stopped" == 1 ]] \
  || { echo "adopted orphan did not stop cleanly; evidence=$evidence_file.orphan-stop.state" >&2; exit 1; }
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp'" >/dev/null
adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r' >"$evidence_file.orphan-final.ps"
if [[ -n "$(all_vpp_process_snapshot || true)" ]]; then
  echo "VPP process appeared during orphan recovery; evidence=$evidence_file.orphan-final.ps" >&2
  exit 1
fi
assert_no_runtime_residue

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
restart_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
assert_exactly_one_owner root "$restart_pid"

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
assert_exactly_one_owner root "$root_fault_pid"
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
if adb_cmd shell "su 0 sh -c 'kill -0 $root_round_pid'" >/dev/null 2>&1; then
  echo "old Root VPP owner remained alive after Root -> VPN switch" >&2
  exit 1
fi
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/root/vpp'" >/dev/null \
  || { echo "old Root profile residue remained after Root -> VPN switch" >&2; exit 1; }
assert_exactly_one_owner vpn "$vpn_pid"
adb_cmd shell input keyevent KEYCODE_HOME
adb_cmd shell am start -n "$activity" >/dev/null
sleep 1
state="$(adb_cmd shell run-as "$package" cat "$state_path" | tr -d '\r')"
grep -q '^state=running$' <<<"$state"
grep -q '^profile=vpn$' <<<"$state"

# Complete the required Root -> VPN -> Root switch. The old VPN PID and its
# entire profile tree must be gone before the new Root owner is accepted.
adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile root >/dev/null
root_return_running=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.root-return.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^profile=root$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state"; then
    root_return_running=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "Root return failed; evidence=$evidence_file.root-return.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$root_return_running" == 1 ]] \
  || { echo "Root return did not reach running; evidence=$evidence_file.root-return.state" >&2; exit 1; }
root_return_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
[[ "$root_return_pid" =~ ^[0-9]+$ && "$root_return_pid" != "$vpn_pid" ]] \
  || { echo "Root return did not publish a new PID" >&2; exit 1; }
if adb_cmd shell "su 0 sh -c 'kill -0 $vpn_pid'" >/dev/null 2>&1; then
  echo "old VPN VPP owner remained alive after VPN -> Root switch" >&2
  exit 1
fi
adb_cmd shell "run-as $package sh -c 'test ! -e files/profiles/vpn/vpp'" >/dev/null \
  || { echo "old VPN profile residue remained after VPN -> Root switch" >&2; exit 1; }
assert_exactly_one_owner root "$root_return_pid"

# First stop the returned healthy Root instance, then leave only app-owned
# VPN profile files with no PID/handle. A fresh VPN start must audit the
# app-UID candidate set,
# delete the safe residue, and recover instead of leaving cleanup_failed.
adb_cmd shell am start -n "$activity" --ez runtimeStop true >/dev/null
for _ in $(seq 1 20); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.vpn-prepid-stop.state"
  if grep -q '^state=stopped$' <<<"$state" \
      && grep -q '^mayBeActive=false$' <<<"$state"; then
    break
  fi
  sleep 1
done
grep -q '^state=stopped$' <<<"$state"
adb_cmd shell run-as "$package" mkdir -p files/profiles/vpn/vpp/runtime files/profiles/vpn/vpp/logs files/profiles/vpn/vpp/shm
adb_cmd shell "run-as $package sh -c 'cd /data/user/0/$package; printf 12345678-1234-1234-1234-123456789abc > files/profiles/vpn/vpp/runtime/owner.token; printf test > files/profiles/vpn/vpp/startup.conf; rm -f files/profiles/vpn/vpp/runtime/vpp.pid'"
adb_cmd shell su 0 sh -c "find /data/user/0/$package/files/profiles/vpn/vpp -maxdepth 3 -print 2>/dev/null | sort" \
  | tr -d '\r' >"$evidence_file.vpn-prepid-residue"
adb_cmd shell am start -n "$activity" --ez runtimeStart true --es runtimeProfile vpn >/dev/null
vpn_prepid_recovered=0
for _ in $(seq 1 30); do
  state="$(adb_cmd shell run-as "$package" cat "$state_path" 2>/dev/null | tr -d '\r' || true)"
  printf '%s\n' "$state" >"$evidence_file.vpn-prepid.state"
  if grep -q '^state=running$' <<<"$state" \
      && grep -q '^profile=vpn$' <<<"$state" \
      && grep -q '^health=ok$' <<<"$state" \
      && ! grep -q '^errorCode=cleanup_failed$' <<<"$state"; then
    vpn_prepid_recovered=1
    break
  fi
  if grep -q '^state=error$' <<<"$state"; then
    echo "VPN pre-PID residue recovery failed; evidence=$evidence_file.vpn-prepid.state" >&2
    exit 1
  fi
  sleep 1
done
[[ "$vpn_prepid_recovered" == 1 ]] \
  || { echo "VPN pre-PID residue did not recover; evidence=$evidence_file.vpn-prepid.state" >&2; exit 1; }
vpn_prepid_pid="$(awk -F= '$1 == "pid" {print $2}' <<<"$state")"
assert_exactly_one_owner vpn "$vpn_prepid_pid"

# Final stop and residue/process proof.
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
assert_no_runtime_residue
final_processes="$(adb_cmd shell su 0 sh -c 'ps -A -o PID,NAME,args' | tr -d '\r' || true)"
printf '%s\n' "$final_processes" >"$evidence_file.final.ps"
if [[ -n "$(all_vpp_process_snapshot || true)" ]]; then
  echo "VPP process residue remains after stop" >&2
  exit 1
fi

echo "android runtime incubator lifecycle: PASS"
echo "evidence=$evidence_file"
