#!/usr/bin/env bash
set -euo pipefail

# S171 / E2 bounded direct-vs-final-topology sample runner.
#
# This runner deliberately avoids the historical S125/S124 POC-7 path.  It
# compares the same app-side L4 stress probe against the same WSL2 LAN fixture
# in two modes:
#
#   direct: VPN stopped, package talks directly to the fixture.
#   oi3:    VPN started in corrected four-owner vpp-oi3-multi mode.
#
# It is a bounded E2 sample, not a release performance benchmark and not the
# legacy copy-investment decision runner.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
HOST="${HOST:-192.168.4.5}"
FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"
UDP_PORT="${UDP_PORT:-42185}"
TCP_PORT="${TCP_PORT:-42186}"
SOURCE_PORT_BASE="${SOURCE_PORT_BASE:-43000}"
TCP_SOURCE_PORT_BASE="${TCP_SOURCE_PORT_BASE:-44000}"
WARMUP_SECONDS="${WARMUP_SECONDS:-1}"
STEADY_SECONDS="${STEADY_SECONDS:-10}"
DRAIN_SECONDS="${DRAIN_SECONDS:-2}"
UDP_CLOSED_TIMEOUT_MS="${UDP_CLOSED_TIMEOUT_MS:-1000}"
UDP_SATURATING_TIMEOUT_MS="${UDP_SATURATING_TIMEOUT_MS:-200}"
TCP_READ_TIMEOUT_MS="${TCP_READ_TIMEOUT_MS:-5000}"
RECONNECT_EVERY="${RECONNECT_EVERY:-0}"
REPEATS="${REPEATS:-1}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s171-e2-oi3-direct-sample-20260825}"
# protocol:flows:payloadBytes:burst:load
CELLS="${CELLS:-udp:1:64:1:closed udp:4:1400:1:closed tcp:1:1400:1:closed}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/cells"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
CSV="$RESULT_DIR/cells-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
FIXTURE_LOG="$RESULT_DIR/fixture-$RUN_ID.log"
FIXTURE_SCRIPT="$RESULT_DIR/fixture-$RUN_ID.py"
REMOTE_FILES="/data/user/0/$PACKAGE/files"
REMOTE_LOGS="$REMOTE_FILES/vpp/logs"
REMOTE_RUNTIME="$REMOTE_FILES/vpp/runtime"
REMOTE_APP_LOG="$REMOTE_FILES/logs/app-l4-stress-probe.log"
REMOTE_CLI_LOG="$REMOTE_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$REMOTE_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$REMOTE_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$REMOTE_LOGS/vpp-protect.log"

exec > >(tee "$RUN_LOG") 2>&1

FIXTURE_PID=""

start_fixture() {
  cat >"$FIXTURE_SCRIPT" <<'PY'
#!/usr/bin/env python3
import selectors
import socket
import sys
import time

bind_host = sys.argv[1]
udp_port = int(sys.argv[2])
tcp_port = int(sys.argv[3])

selector = selectors.DefaultSelector()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.bind((bind_host, udp_port))
udp.setblocking(False)
selector.register(udp, selectors.EVENT_READ, ("udp", None))

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((bind_host, tcp_port))
tcp.listen(128)
tcp.setblocking(False)
selector.register(tcp, selectors.EVENT_READ, ("tcp-listen", None))

print(f"fixture listening udp={bind_host}:{udp_port} tcp={bind_host}:{tcp_port}", flush=True)

udp_rx = udp_tx = tcp_rx = tcp_tx = tcp_conn = 0
conn_ids = {}

while True:
    for key, _ in selector.select(timeout=1.0):
        kind, _ = key.data
        if kind == "udp":
            data, addr = udp.recvfrom(65535)
            udp_rx += 1
            print(f"{time.time():.6f} UDP RX {addr[0]}:{addr[1]} bytes={len(data)} total={udp_rx}", flush=True)
            sent = udp.sendto(data, addr)
            udp_tx += 1
            print(f"{time.time():.6f} UDP TX {addr[0]}:{addr[1]} bytes={sent} total={udp_tx}", flush=True)
        elif kind == "tcp-listen":
            conn, addr = tcp.accept()
            conn.setblocking(False)
            tcp_conn += 1
            conn_ids[conn.fileno()] = tcp_conn
            selector.register(conn, selectors.EVENT_READ, ("tcp", addr))
            print(f"{time.time():.6f} TCP ACCEPT id={tcp_conn} {addr[0]}:{addr[1]}", flush=True)
        else:
            conn = key.fileobj
            addr = key.data[1]
            cid = conn_ids.get(conn.fileno(), -1)
            data = conn.recv(65535)
            if not data:
                selector.unregister(conn)
                conn.close()
                print(f"{time.time():.6f} TCP CLOSE id={cid}", flush=True)
                continue
            tcp_rx += 1
            print(f"{time.time():.6f} TCP RX id={cid} {addr[0]}:{addr[1]} bytes={len(data)} total={tcp_rx}", flush=True)
            conn.sendall(data)
            tcp_tx += 1
            print(f"{time.time():.6f} TCP TX id={cid} {addr[0]}:{addr[1]} bytes={len(data)} total={tcp_tx}", flush=True)
PY
  python3 -u "$FIXTURE_SCRIPT" "$FIXTURE_BIND" "$UDP_PORT" "$TCP_PORT" >"$FIXTURE_LOG" 2>&1 &
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

adb_read() {
  adb_su "$1" | tr -d '\r'
}

stop_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1 || true
  sleep 2
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
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
  for _ in $(seq 1 80); do
    adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$output"
    if grep -q 'oi3_cleanup result=' "$output" 2>/dev/null; then
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

cleanup() {
  stop_vpn
  stop_fixture
}
trap cleanup EXIT

package_uid() {
  adb_su "cmd package list packages -U 2>/dev/null | sed -n 's#^package:$PACKAGE uid:\\([0-9][0-9]*\\).*#\\1#p' | head -n 1" \
    | tr -d '\r\n'
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
  local app_pid vpp_pid hev_pid item resource_label pid
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
      resource_label="${item%%:*}"
      pid="${item#*:}"
      [[ -n "$pid" && "$pid" != 0 ]] || continue
      echo "--- $resource_label status pid=$pid ---"
      adb_read "cat /proc/$pid/status 2>/dev/null || true"
      echo "--- $resource_label stat pid=$pid ---"
      adb_read "cat /proc/$pid/stat 2>/dev/null || true"
      echo "--- $resource_label schedstat pid=$pid ---"
      adb_read "cat /proc/$pid/schedstat 2>/dev/null || true"
      echo "--- $resource_label fd-count pid=$pid ---"
      adb_read "ls -1 /proc/$pid/fd 2>/dev/null | wc -l"
      echo "--- $resource_label task-count pid=$pid ---"
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

kv_from_done() {
  local key="$1" file="$2"
  sed -n "s/.*done runId=.* $key=\\([^ ]*\\).*/\\1/p" "$file" | tail -n 1
}

run_id_from_app() {
  local file="$1"
  sed -n 's/.*start .*runId=\([0-9][0-9]*\).*/\1/p' "$file" | tail -n 1
}

fixture_count() {
  local pattern="$1"
  grep -c "$pattern" "$FIXTURE_LOG" || true
}

wait_vpp_ready() {
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

run_l4_probe() {
  local protocol="$1" flows="$2" payload="$3" burst="$4" load="$5"
  local port="$UDP_PORT" source_port_base="$SOURCE_PORT_BASE"
  [[ "$protocol" == tcp ]] && port="$TCP_PORT" && source_port_base="$TCP_SOURCE_PORT_BASE"
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez appL4StressProbe true \
    --es protocol "$protocol" --es host "$HOST" --ei port "$port" --ei flows "$flows" \
    --ei sourcePortBase "$source_port_base" --ei payloadBytes "$payload" \
    --ei burst "$burst" --es load "$load" \
    --ei warmupSeconds "$WARMUP_SECONDS" --ei steadySeconds "$STEADY_SECONDS" \
    --ei drainSeconds "$DRAIN_SECONDS" --ei reconnectEvery "$RECONNECT_EVERY" \
    --ei udpClosedTimeoutMs "$UDP_CLOSED_TIMEOUT_MS" \
    --ei udpSaturatingTimeoutMs "$UDP_SATURATING_TIMEOUT_MS" \
    --ei tcpReadTimeoutMs "$TCP_READ_TIMEOUT_MS" \
    --ez expectEcho true >/dev/null
}

wait_probe_done() {
  local output="$1" timeout=$((WARMUP_SECONDS + STEADY_SECONDS + DRAIN_SECONDS + 90))
  local app_log="" run_id=""
  for _ in $(seq 1 "$timeout"); do
    app_log="$(adb_read "cat '$REMOTE_APP_LOG' 2>/dev/null || true")"
    run_id="$(sed -n 's/.*start .*runId=\([0-9][0-9]*\).*/\1/p' <<<"$app_log" | tail -n 1)"
    if [[ -n "$run_id" ]] && grep -Eq "(done|fail).*runId=$run_id" <<<"$app_log"; then
      printf '%s\n' "$app_log" >"$output"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$app_log" >"$output"
  return 1
}

write_provenance() {
  local uid="$1" installed_path native_dir
  installed_path="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/base.apk#p' | head -n 1")"
  native_dir="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1")"
  {
    echo "schema=s171-e2-oi3-direct-sample/v1"
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(adb_target_desc)"
    echo "device_model=$(adb_read 'getprop ro.product.model')"
    echo "device_fingerprint=$(adb_read 'getprop ro.build.fingerprint')"
    echo "android_release=$(adb_read 'getprop ro.build.version.release')"
    echo "package=$PACKAGE package_uid=$uid"
    echo "apk_host=$APK"
    echo "apk_sha256=$(sha256sum "$APK" | awk '{print $1}')"
    echo "installed_apk_path=$installed_path"
    echo "installed_apk_sha256=$(adb_read "sha256sum '$installed_path'")"
    echo "device_native_dir=$native_dir"
    echo "device_plugin_sha256=$(adb_read "sha256sum '$native_dir/libhev_external_driver_poc_plugin.so' 2>/dev/null || true")"
    echo "device_hev_sha256=$(adb_read "sha256sum '$native_dir/libhev-socks5-tunnel.so' 2>/dev/null || true")"
    echo "host=$HOST fixture_bind=$FIXTURE_BIND udp_port=$UDP_PORT tcp_port=$TCP_PORT"
    echo "cells=$CELLS"
    echo "repeats=$REPEATS warmupSeconds=$WARMUP_SECONDS steadySeconds=$STEADY_SECONDS drainSeconds=$DRAIN_SECONDS"
    echo "udpClosedTimeoutMs=$UDP_CLOSED_TIMEOUT_MS udpSaturatingTimeoutMs=$UDP_SATURATING_TIMEOUT_MS tcpReadTimeoutMs=$TCP_READ_TIMEOUT_MS"
    echo "sourcePortBase=$SOURCE_PORT_BASE tcpSourcePortBase=$TCP_SOURCE_PORT_BASE"
    echo "fixture_log=$FIXTURE_LOG"
    echo "--- package state ---"
    adb_read "dumpsys package '$PACKAGE' | grep -E 'userId=|requested permissions:|android.permission.(INTERNET|NEARBY_WIFI_DEVICES)|RESTRICT_LOCAL_NETWORK' || true"
    echo "--- networks ---"
    adb_read 'dumpsys connectivity | grep -E "NetworkAgentInfo|TRANSPORT_VPN|NOT_VPN|WIFI|network\{netId" | head -n 120 || true'
    echo "--- git ---"
    echo "git_revision=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  } >"$RESULT_DIR/run-validity-$RUN_ID.txt"
}

run_cell() {
  local mode="$1" protocol="$2" flows="$3" payload="$4" burst="$5" load="$6" repeat="$7"
  local label="${mode}-${protocol}-f${flows}-p${payload}-b${burst}-${load}-r${repeat}"
  local cell="$RESULT_DIR/cells/$label"
  local baseline_rules after_rules vpp_pid="" start_rc=0
  mkdir -p "$cell"
  echo "## cell=$label"
  stop_vpn
  adb_read "rm -f '$REMOTE_APP_LOG' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
  baseline_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$baseline_rules" >"$cell/baseline-ip-rules.txt"

  if [[ "$mode" == oi3 ]]; then
    set +e
    start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
      --ez start true --es mode vpp-oi3-multi --es allowedPackage "$PACKAGE" 2>&1)"
    start_rc=$?
    set -e
    printf '%s\n' "$start_output" >"$cell/start.txt"
    vpp_pid="$(wait_vpp_ready || true)"
    if [[ -z "$vpp_pid" || "$start_rc" != 0 ]]; then
      echo "cell=$label INVALID: OI3 four-owner startup not proven"
      adb_read "cat '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$cell/startup-logs.txt"
      return 1
    fi
    sleep 2
  fi

  snapshot_before="$(process_snapshot)"
  printf '%s\n' "$snapshot_before" >"$cell/processes-before.txt"
  capture_resource before "$snapshot_before" "$uid" "$cell/resource-before.raw"
  run_l4_probe "$protocol" "$flows" "$payload" "$burst" "$load"
  sleep "$WARMUP_SECONDS"
  snapshot_steady="$(process_snapshot)"
  printf '%s\n' "$snapshot_steady" >"$cell/processes-steady.txt"
  capture_resource steady "$snapshot_steady" "$uid" "$cell/resource-steady.raw"
  probe_ok=1
  wait_probe_done "$cell/app.log" || probe_ok=0
  snapshot_after="$(process_snapshot)"
  printf '%s\n' "$snapshot_after" >"$cell/processes-after-probe.txt"
  capture_resource after-probe "$snapshot_after" "$uid" "$cell/resource-after-probe.raw"
  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$cell/vpp-cli.log"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$cell/vpp-stdout.log"
  adb_read "cat '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$cell/vpp-hev.log"
  adb_read "cat '$REMOTE_PROTECT_LOG' 2>/dev/null || true" >"$cell/vpp-protect.log"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' >"$cell/logcat.txt"

  if [[ "$mode" == oi3 ]]; then
    stop_oi3_multi "$cell" || true
  fi
  stop_vpn
  snapshot_stop="$(process_snapshot)"
  printf '%s\n' "$snapshot_stop" >"$cell/processes-after-stop.txt"
  adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$cell/cleanup.log"
  after_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$after_rules" >"$cell/after-ip-rules.txt"

  run_id="$(run_id_from_app "$cell/app.log")"
  sent="$(kv_from_done sent "$cell/app.log")"
  received="$(kv_from_done received "$cell/app.log")"
  errors="$(kv_from_done errors "$cell/app.log")"
  mismatches="$(kv_from_done mismatches "$cell/app.log")"
  unexpected="$(kv_from_done unexpected "$cell/app.log")"
  late="$(kv_from_done late "$cell/app.log")"
  reordered="$(kv_from_done reordered "$cell/app.log")"
  fatal_flows="$(kv_from_done fatalFlows "$cell/app.log")"
  executor_timeout="$(kv_from_done executorTimeout "$cell/app.log")"
  tcp_ready="$(kv_from_done tcpHandshakeReady "$cell/app.log")"
  sent_pps_milli="$(kv_from_done sentPpsMilli "$cell/app.log")"
  received_pps_milli="$(kv_from_done receivedPpsMilli "$cell/app.log")"
  goodput_bps="$(kv_from_done goodputBytesPerSec "$cell/app.log")"
  elapsed_ms="$(kv_from_done elapsedMs "$cell/app.log")"
  cleanup_pass="$(grep -c 'oi3_cleanup result=PASS' "$cell/cleanup.log" || true)"
  cleanup_fail="$(grep -c 'oi3_cleanup result=FAIL' "$cell/cleanup.log" || true)"
  owner_busy="$(grep -c 'reason=owner-busy' "$cell/cleanup.log" || true)"
  tcp_tail_reject="$(awk '/multi-admission result=REJECT/ && /reason=tcp-tail/ {c++} END {print c+0}' "$cell/cleanup.log")"
  multi_reject_non_tail="$(awk '/multi-admission result=REJECT/ && $0 !~ /reason=tcp-tail/ {c++} END {print c+0}' "$cell/cleanup.log")"
  tcp_read_timeout_ms="$(kv_from_done tcpReadTimeoutMs "$cell/app.log")"
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null || true")"
  tun0_after=0
  adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0_after=1 || true
  rules_match=0
  [[ "$baseline_rules" == "$after_rules" ]] && rules_match=1
  app_rss="$(metric_from_resource "$cell/resource-steady.raw" app || true)"
  vpp_rss="$(metric_from_resource "$cell/resource-steady.raw" vpp || true)"
  hev_rss="$(metric_from_resource "$cell/resource-steady.raw" hev || true)"
  app_fd="$(fd_from_resource "$cell/resource-steady.raw" app || true)"
  vpp_fd="$(fd_from_resource "$cell/resource-steady.raw" vpp || true)"
  hev_fd="$(fd_from_resource "$cell/resource-steady.raw" hev || true)"
  app_threads="$(threads_from_resource "$cell/resource-steady.raw" app || true)"
  vpp_threads="$(threads_from_resource "$cell/resource-steady.raw" vpp || true)"
  hev_threads="$(threads_from_resource "$cell/resource-steady.raw" hev || true)"
  udp_rx="$(fixture_count 'UDP RX')"
  udp_tx="$(fixture_count 'UDP TX')"
  tcp_rx="$(fixture_count 'TCP RX')"
  tcp_tx="$(fixture_count 'TCP TX')"

  valid=1
  [[ "$probe_ok" == 1 ]] || valid=0
  [[ -n "${run_id:-}" && "${sent:-0}" != 0 ]] || valid=0
  [[ "${received:-0}" == "${sent:-0}" ]] || valid=0
  [[ "${errors:-999}" == 0 && "${mismatches:-999}" == 0 && "${unexpected:-999}" == 0 ]] || valid=0
  [[ "${reordered:-999}" == 0 && "${fatal_flows:-999}" == 0 && "${executor_timeout:-true}" == false ]] || valid=0
  if [[ "$protocol" == tcp ]]; then
    [[ "${tcp_ready:-false}" == true ]] || valid=0
  fi
  if [[ "$mode" == oi3 ]]; then
    [[ "$cleanup_fail" == 0 && "$cleanup_pass" -gt 0 && "$owner_busy" == 0 && "$multi_reject_non_tail" == 0 ]] || valid=0
  fi
  [[ -z "$residual_vpp" && "$tun0_after" == 0 && "$rules_match" == 1 ]] || valid=0

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$label" "$mode" "$protocol" "$flows" "$payload" "$burst" "$load" "$repeat" \
    "${run_id:-}" "${sent:-0}" "${received:-0}" "${errors:-999}" "${mismatches:-999}" \
    "${unexpected:-999}" "${late:-999}" "${reordered:-999}" "${fatal_flows:-999}" \
    "${executor_timeout:-missing}" "${tcp_ready:-missing}" "${sent_pps_milli:-0}" \
    "${received_pps_milli:-0}" "${goodput_bps:-0}" "${elapsed_ms:-0}" \
    "${app_rss:-0}" "${vpp_rss:-0}" "${hev_rss:-0}" "${app_fd:-0}" "${vpp_fd:-0}" \
    "${hev_fd:-0}" "${app_threads:-0}" "${vpp_threads:-0}" "${hev_threads:-0}" \
    "${tcp_read_timeout_ms:-$TCP_READ_TIMEOUT_MS}" "$cleanup_pass" "$cleanup_fail" \
    "$owner_busy" "$tcp_tail_reject" "$multi_reject_non_tail" "$valid" >>"$CSV"

  echo "cell=$label valid=$valid run_id=${run_id:-missing} sent=${sent:-0} received=${received:-0} goodputBps=${goodput_bps:-0} cleanup=$cleanup_pass/$cleanup_fail ownerBusy=$owner_busy tcpTailReject=$tcp_tail_reject multiRejectNonTail=$multi_reject_non_tail"
  [[ "$valid" == 1 ]]
}

echo "# S171 E2 bounded direct-vs-OI3 sample"
echo "run_id=$RUN_ID"
echo "device=$(adb_target_desc)"
echo "package=$PACKAGE host=$HOST udp=$UDP_PORT tcp=$TCP_PORT cells=$CELLS"
echo "warmup=$WARMUP_SECONDS steady=$STEADY_SECONDS drain=$DRAIN_SECONDS repeats=$REPEATS tcpReadTimeoutMs=$TCP_READ_TIMEOUT_MS"
echo "preflight=adb-start"
device_preflight
echo "preflight=adb-ok"
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }
if [[ "${INSTALL_APK:-1}" == 1 ]]; then
  echo "install=apk-start"
  adb_cmd install -r "$APK" >/dev/null
  echo "install=apk-ok"
fi
uid="$(package_uid)"
[[ -n "$uid" ]] || { echo "package UID unavailable" >&2; exit 1; }
echo "package_uid=$uid"
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
write_provenance "$uid"
echo "fixture=start"
start_fixture
echo "fixture=ready"

printf 'label,mode,protocol,flows,payloadBytes,burst,load,repeat,runId,sent,received,errors,mismatches,unexpected,late,reordered,fatalFlows,executorTimeout,tcpHandshakeReady,sentPpsMilli,receivedPpsMilli,goodputBytesPerSec,elapsedMs,appRssKb,vppRssKb,hevRssKb,appFd,vppFd,hevFd,appThreads,vppThreads,hevThreads,tcpReadTimeoutMs,cleanupPass,cleanupFail,ownerBusy,tcpTailReject,multiRejectNonTail,valid\n' >"$CSV"

failures=0
for repeat in $(seq 1 "$REPEATS"); do
  for spec in $CELLS; do
    IFS=: read -r protocol flows payload burst load <<<"$spec"
    for mode in direct oi3; do
      if ! run_cell "$mode" "$protocol" "$flows" "$payload" "$burst" "$load" "$repeat"; then
        failures=$((failures + 1))
      fi
    done
  done
done

udp_rx="$(fixture_count 'UDP RX')"
udp_tx="$(fixture_count 'UDP TX')"
tcp_rx="$(fixture_count 'TCP RX')"
tcp_tx="$(fixture_count 'TCP TX')"
cat >"$MANIFEST" <<EOF
{
  "schema":"s171-e2-oi3-direct-sample/v1",
  "runId":"$RUN_ID",
  "package":"$PACKAGE",
  "endpoint":"$HOST",
  "fixtureBind":"$FIXTURE_BIND",
  "udpPort":$UDP_PORT,
  "tcpPort":$TCP_PORT,
  "tcpReadTimeoutMs":$TCP_READ_TIMEOUT_MS,
  "cells":"$CELLS",
  "repeats":$REPEATS,
  "warmupSeconds":$WARMUP_SECONDS,
  "steadySeconds":$STEADY_SECONDS,
  "drainSeconds":$DRAIN_SECONDS,
  "apkSha256":"$(sha256sum "$APK" | awk '{print $1}')",
  "pluginSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev_external_driver_poc_plugin.so | sha256sum | awk '{print $1}')",
  "hevSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev-socks5-tunnel.so | sha256sum | awk '{print $1}')",
  "fixtureUdpRx":$udp_rx,
  "fixtureUdpTx":$udp_tx,
  "fixtureTcpRx":$tcp_rx,
  "fixtureTcpTx":$tcp_tx,
  "failureCount":$failures
}
EOF

echo "results=$RESULT_DIR"
echo "csv=$CSV"
echo "manifest=$MANIFEST"
echo "failures=$failures"
[[ "$failures" == 0 ]]
