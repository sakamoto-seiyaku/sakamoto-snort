#!/usr/bin/env bash
set -euo pipefail

# S170 / EG-16 minimum final-topology resource/lifecycle trend cell.
#
# This is deliberately a short repeated envelope, not an E2 performance or
# capacity claim.  It runs the corrected four-owner OI3 Android artifact with
# four concurrent UDP closed-echo flows, captures app/VPP/HEV resource state
# before and after each generation, and requires exact cleanup after every
# generation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-192.168.4.5}"
FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"
PORT="${PORT:-42185}"
FLOWS="${FLOWS:-4}"
SOURCE_PORT_BASE="${SOURCE_PORT_BASE:-43000}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-64}"
LOAD="${LOAD:-closed}"
EXPECT_ECHO="${EXPECT_ECHO:-true}"
WARMUP_SECONDS="${WARMUP_SECONDS:-1}"
STEADY_SECONDS="${STEADY_SECONDS:-6}"
DRAIN_SECONDS="${DRAIN_SECONDS:-2}"
UDP_CLOSED_TIMEOUT_MS="${UDP_CLOSED_TIMEOUT_MS:-1000}"
PREFLIGHT_COUNT="${PREFLIGHT_COUNT:-3}"
PREFLIGHT_PAYLOAD_BYTES="${PREFLIGHT_PAYLOAD_BYTES:-64}"
CYCLES="${CYCLES:-5}"
WAIT_STOP_CLEANUP_ATTEMPTS="${WAIT_STOP_CLEANUP_ATTEMPTS:-28}"
WAIT_OI3_CLEANUP_ATTEMPTS="${WAIT_OI3_CLEANUP_ATTEMPTS:-120}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s170-e1-resource-trend-20260825}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/cycles"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
CSV="$RESULT_DIR/cycles-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
FIXTURE_LOG="$RESULT_DIR/udp-fixture.log"
FIXTURE_SCRIPT="$RESULT_DIR/udp-fixture-$RUN_ID.py"
REMOTE_FILES="/data/user/0/$PACKAGE/files"
REMOTE_LOGS="$REMOTE_FILES/vpp/logs"
REMOTE_RUNTIME="$REMOTE_FILES/vpp/runtime"
REMOTE_APP_LOG="$REMOTE_FILES/logs/app-l4-stress-probe.log"
REMOTE_UDP_PREFLIGHT_LOG="$REMOTE_FILES/logs/app-udp-probe.log"
REMOTE_CLI_LOG="$REMOTE_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$REMOTE_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$REMOTE_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$REMOTE_LOGS/vpp-protect.log"
ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"
ADB_READ_RETRY_DELAY_SECONDS="${ADB_READ_RETRY_DELAY_SECONDS:-1}"

exec > >(tee "$RUN_LOG") 2>&1

FIXTURE_PID=""

start_fixture() {
  cat >"$FIXTURE_SCRIPT" <<'PY'
#!/usr/bin/env python3
import socket
import sys
import time

bind_host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((bind_host, port))
print(f"fixture listening {bind_host}:{port}", flush=True)
rx = 0
tx = 0
total_bytes = 0
while True:
    data, addr = sock.recvfrom(65535)
    rx += 1
    total_bytes += len(data)
    print(f"{time.time():.6f} RX {addr[0]}:{addr[1]} bytes={len(data)} "
          f"total={rx} bytes_total={total_bytes}", flush=True)
    sent = sock.sendto(data, addr)
    tx += 1
    print(f"{time.time():.6f} TX {addr[0]}:{addr[1]} bytes={sent} "
          f"total={tx}", flush=True)
PY
  python3 -u "$FIXTURE_SCRIPT" "$FIXTURE_BIND" "$PORT" >"$FIXTURE_LOG" 2>&1 &
  FIXTURE_PID="$!"
  for _ in $(seq 1 40); do
    if grep -q "fixture listening" "$FIXTURE_LOG" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$FIXTURE_PID" 2>/dev/null; then
      cat "$FIXTURE_LOG" >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "fixture did not become ready" >&2
  cat "$FIXTURE_LOG" >&2 || true
  return 1
}

stop_fixture() {
  if [[ -n "${FIXTURE_PID:-}" ]]; then
    kill "$FIXTURE_PID" >/dev/null 2>&1 || true
    wait "$FIXTURE_PID" >/dev/null 2>&1 || true
    FIXTURE_PID=""
  fi
}

adb_read_once() {
  adb_su "$1" | tr -d '\r'
}

adb_read() {
  local command="$1" attempt rc output had_errexit=0
  for attempt in $(seq 1 "$ADB_READ_RETRY_ATTEMPTS"); do
    case $- in *e*) had_errexit=1 ;; *) had_errexit=0 ;; esac
    set +e
    output="$(adb_read_once "$command" 2>&1)"
    rc=$?
    if [[ "$had_errexit" == 1 ]]; then
      set -e
    fi
    if [[ "$rc" == 0 ]]; then
      printf '%s\n' "$output"
      return 0
    fi
    if [[ "$attempt" -lt "$ADB_READ_RETRY_ATTEMPTS" ]]; then
      echo "adb_read retry attempt=$attempt rc=$rc command=$command" >&2
      sleep "$ADB_READ_RETRY_DELAY_SECONDS"
    fi
  done
  printf '%s\n' "$output" >&2
  return "$rc"
}

wait_stop_cleanup_marker() {
  local marker=""
  for _ in $(seq 1 "$WAIT_STOP_CLEANUP_ATTEMPTS"); do
    marker="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 120 \"\$f\" 2>/dev/null | grep -E 'oi3_cleanup result=' || true; fi; done | tail -n 1")"
    if [[ -n "$marker" ]]; then
      return 0
    fi
    if [[ -z "$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")" ]]; then
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
  local output="$1" cleanup_total
  for _ in $(seq 1 "$WAIT_OI3_CLEANUP_ATTEMPTS"); do
    adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$output"
    if grep -q 'oi4 multi-session state=STOPPED' "$output" 2>/dev/null; then
      return 0
    fi
    cleanup_total="$(grep -c 'oi3_cleanup result=' "$output" 2>/dev/null || true)"
    if [[ "$cleanup_total" -ge 4 ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

stop_oi3_multi() {
  local cell="$1"
  run_oi3_control "multi-stop" "$cell/oi3-control-multi-stop.txt" || return 1
  wait_oi3_cleanup "$cell/cleanup-pre-stop.log"
}

stop_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1 || true
  wait_stop_cleanup_marker || true
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

cleanup() {
  stop_vpn
  stop_fixture
}
trap cleanup EXIT

package_uid() {
  adb_read "cmd package list packages -U 2>/dev/null | sed -n 's#^package:$PACKAGE uid:\\([0-9][0-9]*\\).*#\\1#p' | head -n 1" \
    | tr -d '\n'
}

process_snapshot() {
  adb_read "ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS"
}

find_pid() {
  local snapshot="$1" kind="$2" uid="$3" app_pid="${4:-}"
  case "$kind" in
    app)
      awk -v uid="$uid" -v pkg="$PACKAGE" \
        '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$snapshot"
      ;;
    vpp)
      awk -v uid="$uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$snapshot"
      ;;
    hev)
      awk -v uid="$uid" -v pkg="$PACKAGE" -v parent="$app_pid" \
        '$1 == uid && $5 == pkg && $3 == parent {print $2; exit}' <<<"$snapshot"
      ;;
  esac
}

capture_resource() {
  local phase="$1" snapshot="$2" uid="$3" output="$4"
  local app_pid vpp_pid hev_pid
  app_pid="$(find_pid "$snapshot" app "$uid")"
  vpp_pid="$(find_pid "$snapshot" vpp "$uid")"
  hev_pid="$(find_pid "$snapshot" hev "$uid" "$app_pid")"
  {
    echo "phase=$phase"
    echo "host_time=$(date -Ins)"
    echo "device_time=$(adb_read 'date -Ins')"
    echo "package=$PACKAGE package_uid=$uid"
    echo "app_pid=$app_pid vpp_pid=$vpp_pid hev_pid=$hev_pid"
    echo "--- ps ---"
    printf '%s\n' "$snapshot"
    for item in "app:$app_pid" "vpp:$vpp_pid" "hev:$hev_pid"; do
      label="${item%%:*}"
      pid="${item#*:}"
      [[ -n "$pid" && "$pid" != 0 ]] || continue
      echo "--- $label status pid=$pid ---"
      adb_read "cat /proc/$pid/status 2>/dev/null || true"
      echo "--- $label stat pid=$pid ---"
      adb_read "cat /proc/$pid/stat 2>/dev/null || true"
      echo "--- $label fd-count pid=$pid ---"
      adb_read "ls -1 /proc/$pid/fd 2>/dev/null | wc -l"
      echo "--- $label task-count pid=$pid ---"
      adb_read "ls -1 /proc/$pid/task 2>/dev/null | wc -l"
    done
    echo "--- thermal ---"
    adb_read 'dumpsys thermalservice 2>/dev/null || true'
    echo "--- deviceidle ---"
    adb_read 'dumpsys deviceidle 2>/dev/null || true'
  } >"$output"
}

metric_from_resource() {
  local file="$1" label="$2"
  awk -v label="$label" '$0 ~ "^--- " label " status" {seen=1; next} seen && /^VmRSS:/ {print $2; exit}' "$file"
}

fd_from_resource() {
  local file="$1" label="$2"
  awk -v label="$label" '$0 ~ "^--- " label " fd-count" {getline; print $1; exit}' "$file"
}

threads_from_resource() {
  local file="$1" label="$2"
  awk -v label="$label" '$0 ~ "^--- " label " task-count" {getline; print $1; exit}' "$file"
}

write_provenance() {
  local uid="$1" apk_sha apk_member_plugin apk_member_hev installed_path
  apk_sha="$(sha256sum "$APK" | awk '{print $1}')"
  apk_member_plugin="$(unzip -p "$APK" lib/arm64-v8a/libhev_external_driver_poc_plugin.so | sha256sum | awk '{print $1}')"
  apk_member_hev="$(unzip -p "$APK" lib/arm64-v8a/libhev-socks5-tunnel.so | sha256sum | awk '{print $1}')"
  installed_path="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/base.apk#p' | head -n 1")"
  {
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(adb_target_desc)"
    echo "device_model=$(adb_read 'getprop ro.product.model')"
    echo "device_fingerprint=$(adb_read 'getprop ro.build.fingerprint')"
    echo "android_release=$(adb_read 'getprop ro.build.version.release')"
    echo "package=$PACKAGE package_uid=$uid"
    echo "apk_host=$APK"
    echo "apk_sha256=$apk_sha"
    echo "apk_member_plugin_sha256=$apk_member_plugin"
    echo "apk_member_hev_sha256=$apk_member_hev"
    echo "installed_apk_path=$installed_path"
    echo "installed_apk_sha256=$(adb_read "sha256sum '$installed_path'")"
    echo "device_native_dir=$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1")"
    echo "device_plugin_sha256=$(adb_read "native=\$(pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1); sha256sum \"\$native/libhev_external_driver_poc_plugin.so\"")"
    echo "device_hev_sha256=$(adb_read "native=\$(pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1); sha256sum \"\$native/libhev-socks5-tunnel.so\"")"
    echo "expected_hash_policy=current-artifact-by-default; override S170_EXPECTED_* only for a pre-registered historical rerun"
    echo "hev_stage_expected=${S170_EXPECTED_HEV_SHA256:-$apk_member_hev}"
    echo "plugin_expected=${S170_EXPECTED_PLUGIN_SHA256:-$apk_member_plugin}"
    echo "apk_expected=${S170_EXPECTED_APK_SHA256:-$apk_sha}"
    echo "host=$HOST port=$PORT flows=$FLOWS sourcePortBase=$SOURCE_PORT_BASE payloadBytes=$PAYLOAD_BYTES"
    echo "load=$LOAD expectEcho=$EXPECT_ECHO"
    echo "fixture_bind=$FIXTURE_BIND fixture_log=$FIXTURE_LOG"
    echo "warmupSeconds=$WARMUP_SECONDS steadySeconds=$STEADY_SECONDS drainSeconds=$DRAIN_SECONDS"
    echo "udpClosedTimeoutMs=$UDP_CLOSED_TIMEOUT_MS cycles=$CYCLES"
    echo "--- package state ---"
    adb_read "dumpsys package '$PACKAGE' | grep -E 'userId=|requested permissions:|android.permission.(INTERNET|NEARBY_WIFI_DEVICES)|RESTRICT_LOCAL_NETWORK' || true"
    echo "--- grants ---"
    adb_read "dumpsys package '$PACKAGE' | grep -E 'granted=true|NEARBY_WIFI_DEVICES' || true"
    echo "--- compat ---"
    adb_read "am compat list '$PACKAGE' 2>/dev/null | grep -E 'RESTRICT_LOCAL_NETWORK|NEARBY' || true"
    echo "--- networks ---"
    adb_read 'cmd connectivity diagnostics 2>/dev/null || true'
    # Keep the remote grep expression single-quoted. The repo-local WSL2
    # wrapper routes through Windows adb/cmd.exe; a double-quoted expression
    # lets cmd.exe consume the alternation pipes before Android sees them.
    adb_read "dumpsys connectivity | grep -E 'NetworkAgentInfo|TRANSPORT_VPN|NOT_VPN|WIFI|network\\{netId' | head -n 120 || true"
    echo "--- direct control command ---"
    echo "same-package UDP preflight is captured in preflight-app-udp.log"
    echo "--- git ---"
    echo "git_revision=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  } >"$RESULT_DIR/run-validity-$RUN_ID.txt"
}

wait_vpp_ready() {
  local vpp_pid="" oi3_line=""
  for _ in $(seq 1 120); do
    vpp_pid="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")"
    oi3_line="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 80 \"\$f\" 2>/dev/null | grep -E 'oi4 multi enabled|oi3 multi enabled|show plugins' || true; fi; done | tail -n 12")"
    if [[ -n "$vpp_pid" && "$oi3_line" == *"owners=4"* ]]; then
      printf '%s\n' "$vpp_pid"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

echo "# S170 EG-16 final-topology resource/lifecycle trend"
echo "run_id=$RUN_ID"
echo "device=$(adb_target_desc)"
echo "package=$PACKAGE host=$HOST port=$PORT flows=$FLOWS sourcePortBase=$SOURCE_PORT_BASE"
echo "load=$LOAD expectEcho=$EXPECT_ECHO"
echo "cycles=$CYCLES warmup=$WARMUP_SECONDS steady=$STEADY_SECONDS drain=$DRAIN_SECONDS"
echo "fixture=$FIXTURE_BIND:$PORT"
start_fixture
device_preflight
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }
uid="$(package_uid)"
[[ -n "$uid" ]] || { echo "package UID unavailable" >&2; exit 1; }
echo "package_uid=$uid"

stop_vpn
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
adb_read "rm -f '$REMOTE_APP_LOG' '$REMOTE_UDP_PREFLIGHT_LOG' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
  --ez appUdpProbe true --es host "$HOST" --ei port "$PORT" \
  --ei count "$PREFLIGHT_COUNT" --ei payloadBytes "$PREFLIGHT_PAYLOAD_BYTES" >/dev/null
sleep 3
adb_read "cat '$REMOTE_UDP_PREFLIGHT_LOG' 2>/dev/null || true" >"$RESULT_DIR/preflight-app-udp.log"
if ! grep -Eq "packets=$PREFLIGHT_COUNT received=$PREFLIGHT_COUNT" "$RESULT_DIR/preflight-app-udp.log"; then
  echo "INVALID: same-package VPN-stopped UDP endpoint preflight failed" >&2
  exit 2
fi
write_provenance "$uid"

printf 'cycle,start_rc,run_id,sent,received,errors,app_rss_kb,vpp_rss_kb,hev_rss_kb,app_fd,vpp_fd,hev_fd,app_threads,vpp_threads,hev_threads,cleanup_pass,cleanup_fail,residual_vpp,tun0_after,rules_match,fixture_rx,fixture_tx\n' >"$CSV"
failures=0
for cycle in $(seq 1 "$CYCLES"); do
  cell="$RESULT_DIR/cycles/$(printf '%02d' "$cycle")"
  mkdir -p "$cell"
  echo "## cycle=$cycle"
  stop_vpn
  adb_read "rm -f '$REMOTE_APP_LOG' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
  baseline_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$baseline_rules" >"$cell/baseline-ip-rules.txt"
  set +e
  start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
    --ez start true --es mode vpp-oi3-multi --es allowedPackage "$PACKAGE" 2>&1)"
  start_rc=$?
  set -e
  printf '%s\n' "$start_output" >"$cell/start.txt"
  vpp_pid="$(wait_vpp_ready || true)"
  if [[ -z "$vpp_pid" ]]; then
    echo "cycle=$cycle INVALID: VPP/OI3 four-owner startup not proven" >&2
    adb_read "cat '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$cell/startup-logs.txt"
    failures=$((failures + 1))
    break
  fi
  sleep 2
  snapshot_before="$(process_snapshot)"
  printf '%s\n' "$snapshot_before" >"$cell/processes-before.txt"
  capture_resource before "$snapshot_before" "$uid" "$cell/resource-before.raw"

  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez appL4StressProbe true \
    --es protocol udp --es host "$HOST" --ei port "$PORT" --ei flows "$FLOWS" \
    --ei sourcePortBase "$SOURCE_PORT_BASE" --ei payloadBytes "$PAYLOAD_BYTES" \
    --ei burst 1 --es load "$LOAD" --ei warmupSeconds "$WARMUP_SECONDS" \
    --ei steadySeconds "$STEADY_SECONDS" --ei drainSeconds "$DRAIN_SECONDS" \
    --ei reconnectEvery 0 --ei udpClosedTimeoutMs "$UDP_CLOSED_TIMEOUT_MS" \
    --ez expectEcho "$EXPECT_ECHO" >/dev/null
  run_id=""
  for _ in $(seq 1 90); do
    app_log="$(adb_read "cat '$REMOTE_APP_LOG' 2>/dev/null || true")"
    run_id="$(sed -n 's/.*start .*runId=\([0-9][0-9]*\).*/\1/p' <<<"$app_log" | tail -n 1)"
    [[ -n "$run_id" ]] && grep -Eq "(done|fail).*runId=$run_id" <<<"$app_log" && break
    sleep 1
  done
  printf '%s\n' "$app_log" >"$cell/app.log"
  snapshot_after="$(process_snapshot)"
  printf '%s\n' "$snapshot_after" >"$cell/processes-after-probe.txt"
  capture_resource after-probe "$snapshot_after" "$uid" "$cell/resource-after-probe.raw"
  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$cell/vpp-cli.log"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$cell/vpp-stdout.log"
  adb_read "cat '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$cell/vpp-hev.log"
  adb_read "cat '$REMOTE_PROTECT_LOG' 2>/dev/null || true" >"$cell/vpp-protect.log"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' >"$cell/logcat.txt"

  stop_oi3_multi "$cell" || true
  stop_vpn
  snapshot_after_stop="$(process_snapshot)"
  printf '%s\n' "$snapshot_after_stop" >"$cell/processes-after-stop.txt"
  {
    if [[ -f "$cell/cleanup-pre-stop.log" ]]; then
      echo "--- cleanup pre-stop ---"
      cat "$cell/cleanup-pre-stop.log"
    fi
    echo "--- cleanup post-stop ---"
    adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true"
  } >"$cell/cleanup.log"
  after_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$after_rules" >"$cell/after-ip-rules.txt"
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null || true")"
  tun0_after=0
  adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0_after=1 || true
  rules_match=0
  [[ "$baseline_rules" == "$after_rules" ]] && rules_match=1
  sent="$(sed -n 's/.*done runId=.* sent=\([0-9][0-9]*\).*/\1/p' "$cell/app.log" | tail -n 1)"
  received="$(sed -n 's/.*done runId=.* received=\([0-9][0-9]*\).*/\1/p' "$cell/app.log" | tail -n 1)"
  errors="$(sed -n 's/.*done runId=.* errors=\([0-9][0-9]*\).*/\1/p' "$cell/app.log" | tail -n 1)"
  cleanup_pass="$(grep -c 'oi3_cleanup result=PASS' "$cell/cleanup.log" || true)"
  cleanup_fail="$(grep -c 'oi3_cleanup result=FAIL' "$cell/cleanup.log" || true)"
  app_rss="$(metric_from_resource "$cell/resource-before.raw" app || true)"
  vpp_rss="$(metric_from_resource "$cell/resource-before.raw" vpp || true)"
  hev_rss="$(metric_from_resource "$cell/resource-before.raw" hev || true)"
  app_fd="$(fd_from_resource "$cell/resource-before.raw" app || true)"
  vpp_fd="$(fd_from_resource "$cell/resource-before.raw" vpp || true)"
  hev_fd="$(fd_from_resource "$cell/resource-before.raw" hev || true)"
  app_threads="$(threads_from_resource "$cell/resource-before.raw" app || true)"
  vpp_threads="$(threads_from_resource "$cell/resource-before.raw" vpp || true)"
  hev_threads="$(threads_from_resource "$cell/resource-before.raw" hev || true)"
  fixture_rx="$(grep -c ' RX ' "$FIXTURE_LOG" || true)"
  fixture_tx="$(grep -c ' TX ' "$FIXTURE_LOG" || true)"
  app_ok=0
  if [[ "$EXPECT_ECHO" == true ]]; then
    [[ "${received:-0}" == "${sent:-0}" && "${errors:-999}" == 0 ]] && app_ok=1
  else
    [[ "${sent:-0}" != 0 && "${errors:-999}" == 0 && "$fixture_rx" == "$fixture_tx" ]] && app_ok=1
  fi
  printf '%s\n' "$cycle,$start_rc,$run_id,${sent:-0},${received:-0},${errors:-999},${app_rss:-0},${vpp_rss:-0},${hev_rss:-0},${app_fd:-0},${vpp_fd:-0},${hev_fd:-0},${app_threads:-0},${vpp_threads:-0},${hev_threads:-0},$cleanup_pass,$cleanup_fail,${residual_vpp:-},$tun0_after,$rules_match,$fixture_rx,$fixture_tx" >>"$CSV"
  if [[ "$start_rc" != 0 || -z "$run_id" || "$app_ok" != 1 || "$cleanup_fail" != 0 || "$cleanup_pass" -lt 4 || -n "$residual_vpp" || "$tun0_after" != 0 || "$rules_match" != 1 ]]; then
    echo "cycle=$cycle FAIL start=$start_rc run_id=$run_id sent=$sent received=$received errors=$errors cleanup_pass=$cleanup_pass cleanup_fail=$cleanup_fail residual_vpp=$residual_vpp tun0=$tun0_after rules=$rules_match" >&2
    failures=$((failures + 1))
    break
  fi
  echo "cycle=$cycle PASS run_id=$run_id sent=$sent received=$received rss=$app_rss/$vpp_rss/$hev_rss fd=$app_fd/$vpp_fd/$hev_fd threads=$app_threads/$vpp_threads/$hev_threads cleanup=$cleanup_pass fixture=$fixture_rx/$fixture_tx"
done

fixture_rx="$(grep -c ' RX ' "$FIXTURE_LOG" || true)"
fixture_tx="$(grep -c ' TX ' "$FIXTURE_LOG" || true)"
cat >"$MANIFEST" <<EOF
{
  "schema":"s170-e1-resource-trend/v1",
  "runId":"$RUN_ID",
  "package":"$PACKAGE",
  "endpoint":"$HOST:$PORT",
  "fixtureBind":"$FIXTURE_BIND",
  "flows":$FLOWS,
  "sourcePortBase":$SOURCE_PORT_BASE,
  "payloadBytes":$PAYLOAD_BYTES,
  "load":"$LOAD",
  "expectEcho":$EXPECT_ECHO,
  "warmupSeconds":$WARMUP_SECONDS,
  "steadySeconds":$STEADY_SECONDS,
  "drainSeconds":$DRAIN_SECONDS,
  "udpClosedTimeoutMs":$UDP_CLOSED_TIMEOUT_MS,
  "cyclesRequested":$CYCLES,
  "cyclesRecorded":$(tail -n +2 "$CSV" | wc -l),
  "fixtureRx":$fixture_rx,
  "fixtureTx":$fixture_tx,
  "apkSha256":"$(sha256sum "$APK" | awk '{print $1}')",
  "pluginSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev_external_driver_poc_plugin.so | sha256sum | awk '{print $1}')",
  "hevSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev-socks5-tunnel.so | sha256sum | awk '{print $1}')",
  "failureCount":$failures
}
EOF
echo "results=$RESULT_DIR"
echo "csv=$CSV"
echo "manifest=$MANIFEST"
echo "failures=$failures"
[[ "$failures" == 0 && "$(tail -n +2 "$CSV" | wc -l)" == "$CYCLES" ]]
