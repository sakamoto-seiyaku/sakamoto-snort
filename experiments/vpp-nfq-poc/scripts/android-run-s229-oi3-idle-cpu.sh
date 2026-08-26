#!/usr/bin/env bash
set -euo pipefail

# S229 / E2 OI3 idle CPU diagnostic.
#
# Scope:
#   - start the current vpn-lite APK in final-topology vpp-oi3-multi mode
#   - do not run app HTTP/UDP/TCP probes
#   - sample VPP per-thread /proc CPU and schedstat deltas over a short idle
#     window
#
# This is a hotspot isolation probe, not a full E2 performance verdict.  It is
# intended to distinguish idle VPP worker burn from traffic-induced OI3 cost.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-10}"
START_WAIT="${START_WAIT:-6}"
STOP_WAIT="${STOP_WAIT:-3}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s229-oi3-idle-cpu-20260826}"

ADB="${ADB:-$REPO_ROOT/dev/adb}"
ADB_LIB_READY=0

RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_ROOT="$RESULT_DIR/run-$RUN_ID"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
SUMMARY_CSV="$RESULT_DIR/summary-$RUN_ID.csv"
THREAD_DELTA_CSV="$RESULT_DIR/thread-delta-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
VALIDITY="$RESULT_DIR/run-validity-$RUN_ID.txt"

REMOTE_FILES="/data/user/0/$PACKAGE/files"
REMOTE_LOGS="$REMOTE_FILES/vpp/logs"
REMOTE_RUNTIME="$REMOTE_FILES/vpp/runtime"
REMOTE_CLI_SOCK="$REMOTE_RUNTIME/cli.sock"
REMOTE_CLI_LOG="$REMOTE_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$REMOTE_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$REMOTE_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$REMOTE_LOGS/vpp-protect.log"

mkdir -p "$RUN_ROOT" "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

adb_read() {
  adb_su "$1" | tr -d '\r'
}

apk_has_member() {
  local member="$1"
  unzip -Z1 "$APK" | rg -Fqx "$member"
}

sha256_apk_member() {
  local member="$1"
  if apk_has_member "$member"; then
    unzip -p "$APK" "$member" | sha256sum | awk '{print $1}'
  else
    return 1
  fi
}

require_apk_member() {
  local member="$1" reason="$2"
  if ! apk_has_member "$member"; then
    echo "preflight=FAIL missing_apk_member=$member reason=$reason" >&2
    return 1
  fi
}

preflight_apk() {
  [[ -f "$APK" ]] || { echo "preflight=FAIL missing_apk=$APK" >&2; return 1; }
  require_apk_member "lib/arm64-v8a/libhev_external_driver_poc_plugin.so" \
    "oi3-final-topology"
  require_apk_member "lib/arm64-v8a/libhev-socks5-tunnel.so" \
    "oi3-owner-context"
  require_apk_member "lib/arm64-v8a/libvppctl.so" \
    "idle-worker-cli-diagnostics"
}

stop_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1 || true
  sleep "$STOP_WAIT"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

cleanup() {
  if [[ "$ADB_LIB_READY" == 1 ]]; then
    run_oi3_control "multi-stop" "$RUN_ROOT/cleanup-trap-oi3-control-multi-stop.txt" \
      >/dev/null 2>&1 || true
    wait_oi3_cleanup "$RUN_ROOT/cleanup-trap.log" >/dev/null 2>&1 || true
    stop_vpn
  fi
}
trap cleanup EXIT

package_uid() {
  adb_su "cmd package list packages -U 2>/dev/null | sed -n 's#^package:$PACKAGE uid:\\([0-9][0-9]*\\).*#\\1#p' | head -n 1" \
    | tr -d '\r\n'
}

native_library_dir() {
  adb_read "pm path '$PACKAGE' | sed -n 's#^package:\\(.*\\)/base.apk\$#\\1/lib/arm64#p' | head -n 1"
}

process_snapshot() {
  adb_read "ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS"
}

find_pid() {
  local snapshot="$1" kind="$2" uid="$3"
  case "$kind" in
    app)
      awk -v uid="$uid" -v pkg="$PACKAGE" \
        '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$snapshot"
      ;;
    vpp)
      awk -v uid="$uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$snapshot"
      ;;
  esac
}

count_matches() {
  local pattern="$1" file="$2" count
  count="$(rg -c "$pattern" "$file" 2>/dev/null || true)"
  printf '%s\n' "${count:-0}"
}

wait_vpp_oi3_ready() {
  local vpp_pid="" oi3_line=""
  for _ in $(seq 1 120); do
    vpp_pid="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")"
    oi3_line="$(adb_read "grep -E 'oi4 multi enabled|oi3 multi enabled' '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null | tail -n 12")"
    if [[ -n "$vpp_pid" && "$oi3_line" == *"owners=4"* ]]; then
      printf '%s\n' "$vpp_pid"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

run_oi3_control() {
  local control="$1" output="$2" control_output control_rc
  set +e
  control_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
    --ez start true --es oi3Control "$control" 2>&1)"
  control_rc=$?
  set -e
  {
    echo "control=$control"
    echo "rc=$control_rc"
    printf '%s\n' "$control_output"
  } >"$output"
  [[ "$control_rc" == 0 ]]
}

wait_oi3_cleanup() {
  local output="$1"
  local cleanup_total
  for _ in $(seq 1 120); do
    adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$output"
    if rg -q 'oi4 multi-session state=STOPPED' "$output" 2>/dev/null; then
      return 0
    fi
    cleanup_total="$(count_matches 'oi3_cleanup result=' "$output")"
    if [[ "$cleanup_total" -ge 4 ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

capture_startup_files() {
  adb_read "cat '$REMOTE_RUNTIME/startup.conf' 2>/dev/null || true" >"$RUN_ROOT/startup.conf"
  adb_read "cat '$REMOTE_RUNTIME/startup.exec' 2>/dev/null || true" >"$RUN_ROOT/startup.exec"
  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-cli-start.log"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-stdout-start.log"
}

capture_vpp_cli_snapshot() {
  local phase="$1"
  local snapshot_dir="$RUN_ROOT/cli-$phase"
  local native_dir
  native_dir="$(native_library_dir)"
  mkdir -p "$snapshot_dir"
  {
    echo "phase=$phase"
    echo "native_dir=$native_dir"
    echo "cli_sock=$REMOTE_CLI_SOCK"
    echo "device_time=$(adb_read 'date -Ins')"
  } >"$snapshot_dir/paths.txt"

  if [[ -z "$native_dir" ]]; then
    echo "native library dir unavailable" >"$snapshot_dir/error.txt"
    return 0
  fi

  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show version" \
    | tr -d '\r' >"$snapshot_dir/show-version.txt" 2>&1 || true
  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show threads" \
    | tr -d '\r' >"$snapshot_dir/show-threads.txt" 2>&1 || true
  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show runtime" \
    | tr -d '\r' >"$snapshot_dir/show-runtime.txt" 2>&1 || true
  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show runtime verbose" \
    | tr -d '\r' >"$snapshot_dir/show-runtime-verbose.txt" 2>&1 || true
  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show node" \
    | tr -d '\r' >"$snapshot_dir/show-node.txt" 2>&1 || true
  adb_su "LD_LIBRARY_PATH='$native_dir' '$native_dir/libvppctl.so' -s '$REMOTE_CLI_SOCK' show errors" \
    | tr -d '\r' >"$snapshot_dir/show-errors.txt" 2>&1 || true
}

capture_logs() {
  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-cli.log"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-stdout.log"
  adb_read "cat '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-hev.log"
  adb_read "cat '$REMOTE_PROTECT_LOG' 2>/dev/null || true" >"$RUN_ROOT/vpp-protect.log"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' \
    | tr -d '\r' >"$RUN_ROOT/logcat.txt" || true
}

capture_device_state() {
  local output="$1"
  {
    echo "host_time=$(date -Ins)"
    echo "device_time=$(adb_read 'date -Ins')"
    echo "--- power ---"
    adb_read 'dumpsys power 2>/dev/null || true'
    echo "--- deviceidle ---"
    adb_read 'dumpsys deviceidle 2>/dev/null || true'
    echo "--- thermal ---"
    adb_read 'dumpsys thermalservice 2>/dev/null || true'
    echo "--- battery ---"
    adb_read 'dumpsys battery 2>/dev/null || true'
  } >"$output"
}

capture_vpp_tasks() {
  local phase="$1" pid="$2" output="$3"
  adb_su "p='$pid'; phase='$phase'; \
    echo phase=\$phase; echo pid=\$p; echo device_time=\$(date -Ins); \
    cat /proc/\$p/status 2>/dev/null | grep -E '^(Name|State|Threads|Cpus_allowed_list|VmRSS|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' || true; \
    for t in /proc/\$p/task/*; do \
      [ -d \"\$t\" ] || continue; \
      tid=\${t##*/}; \
      comm=\$(cat \"\$t/comm\" 2>/dev/null || true); \
      cpu=\$(awk '{print \$14 + \$15}' \"\$t/stat\" 2>/dev/null || echo 0); \
      sched=\$(awk '{print \$1}' \"\$t/schedstat\" 2>/dev/null || echo 0); \
      cpus=\$(awk '/^Cpus_allowed_list:/ {print \$2}' \"\$t/status\" 2>/dev/null || true); \
      voluntary=\$(awk '/^voluntary_ctxt_switches:/ {print \$2}' \"\$t/status\" 2>/dev/null || echo 0); \
      nonvoluntary=\$(awk '/^nonvoluntary_ctxt_switches:/ {print \$2}' \"\$t/status\" 2>/dev/null || echo 0); \
      state=\$(awk '/^State:/ {print \$2}' \"\$t/status\" 2>/dev/null || true); \
      printf 'task tid=%s comm=%s state=%s cpuTicks=%s schedRuntimeNs=%s cpusAllowed=%s voluntaryCtx=%s nonvoluntaryCtx=%s\n' \
        \"\$tid\" \"\$comm\" \"\$state\" \"\${cpu:-0}\" \"\${sched:-0}\" \"\${cpus:-}\" \"\${voluntary:-0}\" \"\${nonvoluntary:-0}\"; \
    done" | tr -d '\r' >"$output"
}

task_table_from_raw() {
  local input="$1" output="$2"
  awk '
    BEGIN {
      print "tid,comm,state,cpuTicks,schedRuntimeNs,cpusAllowed,voluntaryCtx,nonvoluntaryCtx"
    }
    /^task / {
      tid = comm = state = cpu = sched = cpus = voluntary = nonvoluntary = ""
      for (i = 2; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == "tid") tid = kv[2]
        else if (kv[1] == "comm") comm = kv[2]
        else if (kv[1] == "state") state = kv[2]
        else if (kv[1] == "cpuTicks") cpu = kv[2]
        else if (kv[1] == "schedRuntimeNs") sched = kv[2]
        else if (kv[1] == "cpusAllowed") cpus = kv[2]
        else if (kv[1] == "voluntaryCtx") voluntary = kv[2]
        else if (kv[1] == "nonvoluntaryCtx") nonvoluntary = kv[2]
      }
      print tid "," comm "," state "," cpu "," sched "," cpus "," voluntary "," nonvoluntary
    }
  ' "$input" >"$output"
}

write_thread_delta_csv() {
  local before_csv="$1" after_csv="$2" output="$3"
  awk -F, '
    BEGIN {
      print "tid,comm,cpusAllowed,beforeCpuTicks,afterCpuTicks,cpuTicksDelta,beforeSchedRuntimeNs,afterSchedRuntimeNs,schedRuntimeNsDelta,beforeVoluntaryCtx,afterVoluntaryCtx,voluntaryCtxDelta,beforeNonvoluntaryCtx,afterNonvoluntaryCtx,nonvoluntaryCtxDelta"
    }
    NR == FNR {
      if (FNR > 1) {
        bcomm[$1] = $2
        bcpu[$1] = $4 + 0
        bsched[$1] = $5 + 0
        bcpus[$1] = $6
        bvol[$1] = $7 + 0
        bnonvol[$1] = $8 + 0
      }
      next
    }
    FNR > 1 {
      tid = $1
      comm = $2
      cpus = $6
      before_cpu = bcpu[tid] + 0
      after_cpu = $4 + 0
      before_sched = bsched[tid] + 0
      after_sched = $5 + 0
      before_vol = bvol[tid] + 0
      after_vol = $7 + 0
      before_nonvol = bnonvol[tid] + 0
      after_nonvol = $8 + 0
      if (cpus == "" && bcpus[tid] != "") cpus = bcpus[tid]
      if (comm == "" && bcomm[tid] != "") comm = bcomm[tid]
      print tid "," comm "," cpus "," before_cpu "," after_cpu "," (after_cpu - before_cpu) "," before_sched "," after_sched "," (after_sched - before_sched) "," before_vol "," after_vol "," (after_vol - before_vol) "," before_nonvol "," after_nonvol "," (after_nonvol - before_nonvol)
    }
  ' "$before_csv" "$after_csv" >"$output"
}

sum_csv_column() {
  local csv="$1" column="$2"
  awk -F, -v column="$column" '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        if ($i == column) idx = i
      }
      next
    }
    idx { sum += $idx + 0 }
    END { print sum + 0 }
  ' "$csv"
}

write_validity() {
  local uid="$1" installed_path native_dir
  installed_path="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\\(.*\\)/base.apk\$#\\1/base.apk#p' | head -n 1")"
  native_dir="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\\(.*\\)/base.apk\$#\\1/lib/arm64#p' | head -n 1")"
  {
    echo "schema=s229-oi3-idle-cpu/v1"
    echo "scope=oi3_idle_cpu_hotspot_isolation_not_full_e2"
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(adb_target_desc)"
    echo "device_model=$(adb_read 'getprop ro.product.model')"
    echo "device_fingerprint=$(adb_read 'getprop ro.build.fingerprint')"
    echo "android_release=$(adb_read 'getprop ro.build.version.release')"
    echo "package=$PACKAGE package_uid=$uid"
    echo "sampleSeconds=$SAMPLE_SECONDS startWait=$START_WAIT stopWait=$STOP_WAIT"
    echo "apk_host=$APK"
    echo "apk_sha256=$(sha256sum "$APK" | awk '{print $1}')"
    echo "apk_oi3_plugin_sha256=$(sha256_apk_member 'lib/arm64-v8a/libhev_external_driver_poc_plugin.so')"
    echo "apk_hev_sha256=$(sha256_apk_member 'lib/arm64-v8a/libhev-socks5-tunnel.so')"
    echo "installed_apk_path=$installed_path"
    echo "installed_apk_sha256=$(adb_read "sha256sum '$installed_path'")"
    echo "device_native_dir=$native_dir"
    echo "device_oi3_plugin_sha256=$(adb_read "sha256sum '$native_dir/libhev_external_driver_poc_plugin.so' 2>/dev/null || true")"
    echo "device_hev_sha256=$(adb_read "sha256sum '$native_dir/libhev-socks5-tunnel.so' 2>/dev/null || true")"
    echo "--- git ---"
    echo "git_revision=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_status_short_begin"
    git -C "$REPO_ROOT" status --short 2>/dev/null || true
    echo "git_status_short_end"
  } >"$VALIDITY"
}

echo "# S229 OI3 idle CPU diagnostic"
echo "run_id=$RUN_ID"
echo "package=$PACKAGE sampleSeconds=$SAMPLE_SECONDS resultDir=$RESULT_DIR"
echo "preflight=apk"
preflight_apk
export ADB
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
ADB_LIB_READY=1
echo "device=$(adb_target_desc)"
echo "preflight=adb-start"
device_preflight
echo "preflight=adb-ok"
if [[ "${INSTALL_APK:-1}" == 1 ]]; then
  echo "install=apk-start"
  adb_cmd install -r "$APK" >/dev/null
  echo "install=apk-ok"
fi

uid="$(package_uid)"
[[ -n "$uid" ]] || { echo "package UID unavailable" >&2; exit 1; }
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
write_validity "$uid"

stop_vpn
adb_read "rm -f '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
baseline_rules="$(adb_read 'ip rule show')"
printf '%s\n' "$baseline_rules" >"$RUN_ROOT/baseline-ip-rules.txt"
capture_device_state "$RUN_ROOT/device-state-before.txt"

echo "start=oi3"
set +e
start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
  --ez start true --es mode vpp-oi3-multi --es allowedPackage "$PACKAGE" 2>&1)"
start_rc=$?
set -e
printf '%s\n' "$start_output" >"$RUN_ROOT/start.txt"
vpp_pid="$(wait_vpp_oi3_ready || true)"
startup_valid=0
[[ "$start_rc" == 0 && -n "$vpp_pid" ]] && startup_valid=1
echo "startupValid=$startup_valid vppPid=${vpp_pid:-0}"

if [[ "$startup_valid" != 1 ]]; then
  capture_logs
  echo "startup failed" >&2
  exit 1
fi

sleep "$START_WAIT"
capture_startup_files
snapshot_before="$(process_snapshot)"
printf '%s\n' "$snapshot_before" >"$RUN_ROOT/processes-before.txt"
app_pid="$(find_pid "$snapshot_before" app "$uid")"
vpp_pid="$(find_pid "$snapshot_before" vpp "$uid")"
[[ -n "$vpp_pid" && "$vpp_pid" != 0 ]] || { echo "vpp pid unavailable after start" >&2; exit 1; }
echo "sample=before appPid=${app_pid:-0} vppPid=$vpp_pid"
capture_vpp_cli_snapshot "before"
capture_vpp_tasks before "$vpp_pid" "$RUN_ROOT/vpp-tasks-before.raw"
task_table_from_raw "$RUN_ROOT/vpp-tasks-before.raw" "$RUN_ROOT/vpp-tasks-before.csv"

echo "idle=sleep seconds=$SAMPLE_SECONDS"
sleep "$SAMPLE_SECONDS"

snapshot_after="$(process_snapshot)"
printf '%s\n' "$snapshot_after" >"$RUN_ROOT/processes-after-idle.txt"
vpp_pid_after="$(find_pid "$snapshot_after" vpp "$uid")"
[[ -n "$vpp_pid_after" && "$vpp_pid_after" != 0 ]] || { echo "vpp pid unavailable after idle" >&2; exit 1; }
echo "sample=after vppPid=$vpp_pid_after"
capture_vpp_cli_snapshot "after"
capture_vpp_tasks after "$vpp_pid_after" "$RUN_ROOT/vpp-tasks-after.raw"
task_table_from_raw "$RUN_ROOT/vpp-tasks-after.raw" "$RUN_ROOT/vpp-tasks-after.csv"
write_thread_delta_csv "$RUN_ROOT/vpp-tasks-before.csv" "$RUN_ROOT/vpp-tasks-after.csv" "$THREAD_DELTA_CSV"

vpp_cpu_delta="$(sum_csv_column "$THREAD_DELTA_CSV" cpuTicksDelta)"
vpp_sched_delta="$(sum_csv_column "$THREAD_DELTA_CSV" schedRuntimeNsDelta)"
before_tasks="$(awk 'END {if (NR > 0) print NR - 1; else print 0}' "$RUN_ROOT/vpp-tasks-before.csv")"
after_tasks="$(awk 'END {if (NR > 0) print NR - 1; else print 0}' "$RUN_ROOT/vpp-tasks-after.csv")"

run_oi3_control "multi-stop" "$RUN_ROOT/oi3-control-multi-stop.txt" || true
wait_oi3_cleanup "$RUN_ROOT/cleanup-pre-stop.log" || true
cleanup_pass="$(count_matches 'oi3_cleanup result=PASS' "$RUN_ROOT/cleanup-pre-stop.log")"
cleanup_fail="$(count_matches 'oi3_cleanup result=FAIL' "$RUN_ROOT/cleanup-pre-stop.log")"
capture_logs
stop_vpn
capture_device_state "$RUN_ROOT/device-state-after.txt"
snapshot_stop="$(process_snapshot)"
printf '%s\n' "$snapshot_stop" >"$RUN_ROOT/processes-after-stop.txt"
residual_vpp="$(adb_read "pidof vpp 2>/dev/null || true")"
tun0_after=0
adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0_after=1 || true
after_rules="$(adb_read 'ip rule show')"
printf '%s\n' "$after_rules" >"$RUN_ROOT/after-ip-rules.txt"
rules_match=0
[[ "$baseline_rules" == "$after_rules" ]] && rules_match=1

valid=1
[[ "$startup_valid" == 1 && "$before_tasks" -gt 0 && "$after_tasks" -gt 0 ]] || valid=0
[[ "$cleanup_fail" == 0 && "$cleanup_pass" -gt 0 ]] || valid=0
[[ -z "$residual_vpp" && "$tun0_after" == 0 && "$rules_match" == 1 ]] || valid=0

printf 'runId,sampleSeconds,startupValid,beforeTasks,afterTasks,vppCpuTicksDelta,vppSchedRuntimeNsDelta,cleanupPass,cleanupFail,residualVpp,tun0After,rulesMatch,valid\n' >"$SUMMARY_CSV"
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
  "$RUN_ID" "$SAMPLE_SECONDS" "$startup_valid" "$before_tasks" "$after_tasks" \
  "$vpp_cpu_delta" "$vpp_sched_delta" "$cleanup_pass" "$cleanup_fail" \
  "${residual_vpp:-}" "$tun0_after" "$rules_match" "$valid" >>"$SUMMARY_CSV"

cat >"$MANIFEST" <<EOF
{
  "schema":"s229-oi3-idle-cpu/v1",
  "scope":"oi3_idle_cpu_hotspot_isolation_not_full_e2",
  "runId":"$RUN_ID",
  "package":"$PACKAGE",
  "sampleSeconds":$SAMPLE_SECONDS,
  "startupValid":$startup_valid,
  "beforeTasks":$before_tasks,
  "afterTasks":$after_tasks,
  "vppCpuTicksDelta":$vpp_cpu_delta,
  "vppSchedRuntimeNsDelta":$vpp_sched_delta,
  "cleanupPass":$cleanup_pass,
  "cleanupFail":$cleanup_fail,
  "residualVpp":"${residual_vpp:-}",
  "tun0After":$tun0_after,
  "rulesMatch":$rules_match,
  "valid":$valid,
  "runRoot":"$RUN_ROOT",
  "summaryCsv":"$SUMMARY_CSV",
  "threadDeltaCsv":"$THREAD_DELTA_CSV",
  "apkSha256":"$(sha256sum "$APK" | awk '{print $1}')",
  "oi3PluginSha256":"$(sha256_apk_member 'lib/arm64-v8a/libhev_external_driver_poc_plugin.so')",
  "hevSha256":"$(sha256_apk_member 'lib/arm64-v8a/libhev-socks5-tunnel.so')"
}
EOF

echo "summary=$SUMMARY_CSV"
echo "threadDelta=$THREAD_DELTA_CSV"
echo "manifest=$MANIFEST"
echo "validity=$VALIDITY"
echo "valid=$valid startup=$startup_valid tasks=$before_tasks/$after_tasks cpuTicksDelta=$vpp_cpu_delta schedRuntimeNsDelta=$vpp_sched_delta cleanup=$cleanup_pass/$cleanup_fail"
[[ "$valid" == 1 ]]
