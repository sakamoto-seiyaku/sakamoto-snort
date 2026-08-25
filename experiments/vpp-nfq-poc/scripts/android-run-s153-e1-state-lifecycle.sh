#!/usr/bin/env bash
set -euo pipefail

# S153 / E1 residual lifecycle and device-state companion runner.
#
# The S170 runner owns the five-cycle foreground resource trend and S178 owns
# the six-cell dual-stack DNS matrix.  This runner covers the remaining
# stateful E1 cells: normal stop/start, one real Wi-Fi underlay epoch loss and
# replacement, one explicit fault/restart, and screen-off/forced-Doze/wake
# snapshots.  It is bounded evidence collection, not a battery or performance
# certification runner.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST="${HOST:-192.168.4.5}"
FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"
UDP_PORT="${UDP_PORT:-42353}"
TCP_PORT="${TCP_PORT:-42354}"
SOURCE_PORT_BASE="${SOURCE_PORT_BASE:-46530}"
TCP_SOURCE_PORT_BASE="${TCP_SOURCE_PORT_BASE:-47530}"
FLOWS="${FLOWS:-4}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-64}"
UDP_EXPECT_ECHO="${UDP_EXPECT_ECHO:-false}"
WARMUP_SECONDS="${WARMUP_SECONDS:-1}"
STEADY_SECONDS="${STEADY_SECONDS:-8}"
DRAIN_SECONDS="${DRAIN_SECONDS:-1}"
TCP_READ_TIMEOUT_MS="${TCP_READ_TIMEOUT_MS:-5000}"
UDP_CLOSED_TIMEOUT_MS="${UDP_CLOSED_TIMEOUT_MS:-1000}"
ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"
ADB_READ_RETRY_DELAY_SECONDS="${ADB_READ_RETRY_DELAY_SECONDS:-1}"
WAIT_VPP_READY_ATTEMPTS="${WAIT_VPP_READY_ATTEMPTS:-120}"
WAIT_OI3_CLEANUP_ATTEMPTS="${WAIT_OI3_CLEANUP_ATTEMPTS:-120}"
WAIT_STOP_CLEANUP_ATTEMPTS="${WAIT_STOP_CLEANUP_ATTEMPTS:-28}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s153-e1-residual-20260826/state-lifecycle}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
CSV="$RESULT_DIR/phases-$RUN_ID.csv"
FIXTURE_LOG="$RESULT_DIR/fixture-$RUN_ID.log"
FIXTURE_SCRIPT="$RESULT_DIR/fixture-$RUN_ID.py"

REMOTE_FILES="/data/user/0/$PACKAGE/files"
REMOTE_LOGS="$REMOTE_FILES/vpp/logs"
REMOTE_APP_LOG="$REMOTE_FILES/logs/app-l4-stress-probe.log"
REMOTE_CLI_LOG="$REMOTE_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$REMOTE_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$REMOTE_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$REMOTE_LOGS/vpp-protect.log"

exec > >(tee "$RUN_LOG") 2>&1

FIXTURE_PID=""
WIFI_WAS_DISABLED=0
PHASE_FAILURES=0

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
            try:
                data = conn.recv(65535)
            except OSError:
                data = b""
            if not data:
                try:
                    selector.unregister(conn)
                except Exception:
                    pass
                conn.close()
                print(f"{time.time():.6f} TCP CLOSE id={cid}", flush=True)
                continue
            tcp_rx += 1
            print(f"{time.time():.6f} TCP RX id={cid} {addr[0]}:{addr[1]} bytes={len(data)} total={tcp_rx}", flush=True)
            try:
                conn.sendall(data)
                tcp_tx += 1
                print(f"{time.time():.6f} TCP TX id={cid} {addr[0]}:{addr[1]} bytes={len(data)} total={tcp_tx}", flush=True)
            except OSError:
                print(f"{time.time():.6f} TCP TX-ERROR id={cid}", flush=True)
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
    [[ "$had_errexit" == 1 ]] && set -e
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

process_snapshot() {
  adb_read 'ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS'
}

package_uid() {
  adb_read "cmd package list packages -U 2>/dev/null | sed -n 's#^package:$PACKAGE uid:\\([0-9][0-9]*\\).*#\\1#p' | head -n 1" | tr -d '\n'
}

find_pid() {
  local snapshot="$1" kind="$2" uid="$3" app_pid="${4:-}"
  case "$kind" in
    app) awk -v uid="$uid" -v pkg="$PACKAGE" '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$snapshot" ;;
    vpp) awk -v uid="$uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$snapshot" ;;
    hev) awk -v uid="$uid" -v pkg="$PACKAGE" -v parent="$app_pid" '$1 == uid && $5 == pkg && $3 == parent {print $2; exit}' <<<"$snapshot" ;;
  esac
}

capture_state() {
  local label="$1" snapshot app_pid vpp_pid hev_pid phase_dir
  phase_dir="$CURRENT_PHASE_DIR"
  mkdir -p "$phase_dir/state-$label"
  snapshot="$(process_snapshot)"
  printf '%s\n' "$snapshot" >"$phase_dir/state-$label/processes.txt"
  adb_read 'dumpsys power 2>/dev/null || true' >"$phase_dir/state-$label/power.txt"
  adb_read 'dumpsys deviceidle 2>/dev/null || true' >"$phase_dir/state-$label/deviceidle.txt"
  adb_read 'dumpsys battery 2>/dev/null || true' >"$phase_dir/state-$label/battery.txt"
  adb_read 'dumpsys thermalservice 2>/dev/null || true' >"$phase_dir/state-$label/thermal.txt"
  adb_read "dumpsys connectivity | grep -E 'NetworkAgentInfo|TRANSPORT_VPN|NOT_VPN|WIFI|network\\{netId' | head -n 160 || true" >"$phase_dir/state-$label/connectivity.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' >"$phase_dir/state-$label/logcat.txt"
  app_pid="$(find_pid "$snapshot" app "$PACKAGE_UID")"
  vpp_pid="$(find_pid "$snapshot" vpp "$PACKAGE_UID")"
  hev_pid="$(find_pid "$snapshot" hev "$PACKAGE_UID" "$app_pid")"
  {
    echo "label=$label"
    echo "host_time=$(date -Ins)"
    echo "device_time=$(adb_read 'date -Ins')"
    echo "app_pid=$app_pid vpp_pid=$vpp_pid hev_pid=$hev_pid"
    for item in "app:$app_pid" "vpp:$vpp_pid" "hev:$hev_pid"; do
      kind="${item%%:*}"; pid="${item#*:}"
      [[ -n "$pid" && "$pid" != 0 ]] || continue
      echo "--- $kind status pid=$pid ---"
      adb_read "cat /proc/$pid/status 2>/dev/null || true"
      echo "--- $kind stat pid=$pid ---"
      adb_read "cat /proc/$pid/stat 2>/dev/null || true"
      echo "--- $kind schedstat pid=$pid ---"
      adb_read "cat /proc/$pid/schedstat 2>/dev/null || true"
      echo "--- $kind fd-count pid=$pid ---"
      adb_read "ls -1 /proc/$pid/fd 2>/dev/null | wc -l"
      echo "--- $kind task-count pid=$pid ---"
      adb_read "ls -1 /proc/$pid/task 2>/dev/null | wc -l"
    done
  } >"$phase_dir/state-$label/resources.raw"
}

wait_stop_cleanup_marker() {
  local marker=""
  for _ in $(seq 1 "$WAIT_STOP_CLEANUP_ATTEMPTS"); do
    marker="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 120 \"\$f\" 2>/dev/null | grep -E 'oi3_cleanup result=' || true; fi; done | tail -n 1")"
    [[ -n "$marker" ]] && return 0
    [[ -z "$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")" ]] && return 0
    sleep 0.25
  done
  return 1
}

run_oi3_control() {
  local control="$1" output="$2" control_output control_rc
  set +e
  control_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez start true --es oi3Control "$control" 2>&1)"
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
    cleanup_total="$(grep -c 'oi3_cleanup result=' "$output" 2>/dev/null || true)"
    [[ "$cleanup_total" -ge 4 ]] && return 0
    grep -q 'oi4 multi-session state=STOPPED' "$output" 2>/dev/null && return 0
    sleep 0.25
  done
  return 1
}

stop_oi3_multi() {
  local phase_dir="$1"
  mkdir -p "$phase_dir"
  run_oi3_control multi-stop "$phase_dir/oi3-control-multi-stop.txt" || return 1
  wait_oi3_cleanup "$phase_dir/cleanup-pre-stop.log"
}

stop_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  wait_stop_cleanup_marker || true
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

start_vpn() {
  adb_read "rm -f '$REMOTE_APP_LOG' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
  set +e
  start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez start true --es mode vpp-oi3-multi --es allowedPackage "$PACKAGE" 2>&1)"
  start_rc=$?
  set -e
  printf '%s\n' "$start_output" >"$CURRENT_PHASE_DIR/start.txt"
  [[ "$start_rc" == 0 ]] || return 1
  for _ in $(seq 1 "$WAIT_VPP_READY_ATTEMPTS"); do
    vpp_pid="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")"
    oi3_line="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 80 \"\$f\" 2>/dev/null | grep -E 'oi4 multi enabled|oi3 multi enabled|show plugins' || true; fi; done | tail -n 12")"
    if [[ -n "$vpp_pid" && "$oi3_line" == *"owners=4"* ]]; then
      sleep 2
      return 0
    fi
    sleep 0.25
  done
  return 1
}

start_probe() {
  local protocol="$1" port="$2" source_base="$3" steady="$4"
  local expect_echo=true
  if [[ "$protocol" == udp ]]; then
    expect_echo="$UDP_EXPECT_ECHO"
  fi
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez appL4StressProbe true \
    --es protocol "$protocol" --es host "$HOST" --ei port "$port" --ei flows "$FLOWS" \
    --ei sourcePortBase "$source_base" --ei payloadBytes "$PAYLOAD_BYTES" --ei burst 1 \
    --es load closed --ei warmupSeconds "$WARMUP_SECONDS" --ei steadySeconds "$steady" \
    --ei drainSeconds "$DRAIN_SECONDS" --ei reconnectEvery 0 \
    --ei udpClosedTimeoutMs "$UDP_CLOSED_TIMEOUT_MS" --ei tcpReadTimeoutMs "$TCP_READ_TIMEOUT_MS" \
    --ez expectEcho "$expect_echo" >/dev/null
}

wait_probe() {
  local output="$1" timeout=$((STEADY_SECONDS + WARMUP_SECONDS + DRAIN_SECONDS + 45)) app_log="" run_id=""
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

capture_logs() {
  local phase_dir="$1"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$phase_dir/vpp-stdout.log"
  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$phase_dir/vpp-cli.log"
  adb_read "cat '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$phase_dir/vpp-hev.log"
  adb_read "cat '$REMOTE_PROTECT_LOG' 2>/dev/null || true" >"$phase_dir/vpp-protect.log"
}

write_phase_cleanup_log() {
  local output="$1" dir
  shift
  {
    for dir in "$@"; do
      echo "--- cleanup segment $dir ---"
      [[ -f "$dir/cleanup-pre-stop.log" ]] && cat "$dir/cleanup-pre-stop.log"
      [[ -f "$dir/vpp-stdout.log" ]] && cat "$dir/vpp-stdout.log"
      [[ -f "$dir/vpp-cli.log" ]] && cat "$dir/vpp-cli.log"
    done
  } >"$output"
}

normalize_ip_rules() {
  sed -E \
    -e '/lookup wlan0[[:space:]]*$/ s/fwmark 0x[0-9a-f]+\/0x1ffff/fwmark <wlan>\/0x1ffff/g' \
    -e '/lookup wlan0[[:space:]]*$/ s/fwmark 0x[0-9a-f]+\/0xffff/fwmark <wlan>\/0xffff/g' \
    "$1"
}

finalize_phase() {
  local phase="$1" phase_dir="$2" expected="$3" status=0 cleanup_pass cleanup_fail residual tun0 rules
  if [[ ! -f "$phase_dir/vpp-stdout.log" || ! -f "$phase_dir/vpp-cli.log" ]]; then
    capture_logs "$phase_dir"
  fi
  if [[ ! -f "$phase_dir/cleanup.log" ]]; then
    {
      [[ -f "$phase_dir/cleanup-pre-stop.log" ]] && { echo '--- cleanup pre-stop ---'; cat "$phase_dir/cleanup-pre-stop.log"; }
      echo '--- cleanup post-stop ---'
      cat "$phase_dir/vpp-stdout.log" "$phase_dir/vpp-cli.log"
    } >"$phase_dir/cleanup.log"
  fi
  cleanup_pass="$(grep -c 'oi3_cleanup result=PASS' "$phase_dir/cleanup.log" 2>/dev/null || true)"
  cleanup_fail="$(grep -c 'oi3_cleanup result=FAIL' "$phase_dir/cleanup.log" 2>/dev/null || true)"
  residual="$(adb_read 'pidof vpp 2>/dev/null || true')"
  tun0=0
  adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0=1 || true
  rules=1
  if [[ -f "$phase_dir/baseline-ip-rules.txt" ]]; then
    adb_read 'ip rule show' >"$phase_dir/after-ip-rules.txt"
    cmp -s "$phase_dir/baseline-ip-rules.txt" "$phase_dir/after-ip-rules.txt" || rules=0
    if [[ "$rules" == 0 && "$expected" == epoch ]]; then
      normalize_ip_rules "$phase_dir/baseline-ip-rules.txt" >"$phase_dir/baseline-ip-rules.normalized.txt"
      normalize_ip_rules "$phase_dir/after-ip-rules.txt" >"$phase_dir/after-ip-rules.normalized.txt"
      cmp -s "$phase_dir/baseline-ip-rules.normalized.txt" "$phase_dir/after-ip-rules.normalized.txt" && rules=1
    fi
  fi
  printf 'cleanup_pass=%s cleanup_fail=%s residual_vpp=%s tun0_after=%s rules_match=%s\n' "$cleanup_pass" "$cleanup_fail" "$residual" "$tun0" "$rules" >"$phase_dir/verdict.txt"
  [[ "$cleanup_fail" == 0 && "$cleanup_pass" -ge 4 && -z "$residual" && "$tun0" == 0 && "$rules" == 1 ]] || status=1
  case "$expected" in
    epoch)
      rg -q 'underlay epoch reason=lost|underlay epoch published.*available=0' "$phase_dir" || status=1
      rg -q 'underlay epoch reason=available|underlay epoch published.*available=1' "$phase_dir" || status=1
      rg -q 'epoch-invalidated|PASS_EXPECTED_UNDERLAY_INVALIDATION' "$phase_dir" || status=1
      ;;
    fault)
      rg -q 'fault-injected' "$phase_dir" || status=1
      rg -q 'PASS_EXPECTED_FAULT' "$phase_dir" || status=1
      ;;
    screen-off)
      rg -q 'mScreenOn=false|mInteractive=false|mWakefulness=Asleep|mWakefulness=Dozing' "$phase_dir/state-screen-off/power.txt" || status=1
      ;;
    doze)
      rg -q 'mState=IDLE|mState=IDLE_MAINTENANCE' "$phase_dir/state-forced-doze/deviceidle.txt" || status=1
      ;;
  esac
  printf '%s,%s,%s,%s,%s,%s,%s\n' "$phase" "$status" "$cleanup_pass" "$cleanup_fail" "$residual" "$tun0" "$rules" >>"$CSV"
  echo "phase=$phase status=$status cleanup=$cleanup_pass/$cleanup_fail residue=$residual tun0=$tun0 rules=$rules"
  [[ "$status" == 0 ]] || PHASE_FAILURES=$((PHASE_FAILURES + 1))
}

run_foreground_state() {
  local phase="$1" state="$2" phase_dir
  phase_dir="$RESULT_DIR/$phase"
  CURRENT_PHASE_DIR="$phase_dir"; mkdir -p "$phase_dir"
  stop_vpn
  adb_read 'ip rule show' >"$phase_dir/baseline-ip-rules.txt"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  capture_state before
  start_probe udp "$UDP_PORT" "$SOURCE_PORT_BASE" "$STEADY_SECONDS"
  sleep 2
  if [[ "$state" == screen-off ]]; then
    adb_cmd shell input keyevent 26 >/dev/null
    sleep 3
    capture_state screen-off
  else
    adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
    sleep 2
    adb_cmd shell dumpsys deviceidle force-idle >"$phase_dir/force-idle-command.txt"
    sleep 3
    capture_state forced-doze
  fi
  wait_probe "$phase_dir/app.log" || true
  adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
  sleep 3
  capture_state wake
  stop_oi3_multi "$phase_dir" || true
  stop_vpn
  finalize_phase "$phase" "$phase_dir" "$state"
}

run_normal_restart() {
  local phase=normal-stop-start phase_dir="$RESULT_DIR/normal-stop-start"
  CURRENT_PHASE_DIR="$phase_dir"; mkdir -p "$phase_dir"
  stop_vpn
  adb_read 'ip rule show' >"$phase_dir/baseline-ip-rules.txt"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  capture_state before
  start_probe udp "$UDP_PORT" "$SOURCE_PORT_BASE" "$STEADY_SECONDS"
  wait_probe "$phase_dir/app-first.log" || true
  capture_state first-done
  stop_oi3_multi "$phase_dir/first" 2>/dev/null || true
  stop_vpn
  capture_logs "$phase_dir/first"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  capture_state restart
  start_probe udp "$UDP_PORT" "$((SOURCE_PORT_BASE + 10))" "$STEADY_SECONDS"
  wait_probe "$phase_dir/app-restart.log" || true
  capture_state restart-done
  stop_oi3_multi "$phase_dir/restart" 2>/dev/null || true
  stop_vpn
  capture_logs "$phase_dir/restart"
  write_phase_cleanup_log "$phase_dir/cleanup.log" "$phase_dir/first" "$phase_dir/restart"
  finalize_phase "$phase" "$phase_dir" normal
}

run_fault_restart() {
  local phase=fault-restart phase_dir
  phase_dir="$RESULT_DIR/$phase"
  CURRENT_PHASE_DIR="$phase_dir"; mkdir -p "$phase_dir"
  stop_vpn
  adb_read 'ip rule show' >"$phase_dir/baseline-ip-rules.txt"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  capture_state before
  start_probe tcp "$TCP_PORT" "$TCP_SOURCE_PORT_BASE" "$STEADY_SECONDS"
  sleep 2
  run_oi3_control multi-fault-0 "$phase_dir/oi3-control-multi-fault-0.txt" || true
  wait_probe "$phase_dir/app-fault.log" || true
  capture_state fault-done
  stop_oi3_multi "$phase_dir" || true
  stop_vpn
  capture_logs "$phase_dir"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  start_probe udp "$UDP_PORT" "$((SOURCE_PORT_BASE + 20))" "$STEADY_SECONDS"
  wait_probe "$phase_dir/app-restart.log" || true
  capture_state restart-done
  stop_oi3_multi "$phase_dir/restart" 2>/dev/null || true
  stop_vpn
  capture_logs "$phase_dir/restart"
  write_phase_cleanup_log "$phase_dir/cleanup.log" "$phase_dir" "$phase_dir/restart"
  finalize_phase "$phase" "$phase_dir" fault
}

run_epoch_restart() {
  local phase=epoch-restart phase_dir
  phase_dir="$RESULT_DIR/$phase"
  CURRENT_PHASE_DIR="$phase_dir"; mkdir -p "$phase_dir"
  stop_vpn
  adb_read 'ip rule show' >"$phase_dir/baseline-ip-rules.txt"
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  capture_state before
  start_probe udp "$UDP_PORT" "$((SOURCE_PORT_BASE + 20))" 12
  sleep 2
  capture_state epoch-before
  adb_cmd shell svc wifi disable
  WIFI_WAS_DISABLED=1
  sleep 5
  capture_state epoch-lost
  adb_cmd shell svc wifi enable
  WIFI_WAS_DISABLED=0
  sleep 8
  capture_state epoch-available
  wait_probe "$phase_dir/app-transition.log" || true
  capture_logs "$phase_dir"
  stop_oi3_multi "$phase_dir" || true
  stop_vpn
  start_vpn || { PHASE_FAILURES=$((PHASE_FAILURES + 1)); return; }
  start_probe udp "$UDP_PORT" "$((SOURCE_PORT_BASE + 30))" "$STEADY_SECONDS"
  wait_probe "$phase_dir/app-restart.log" || true
  capture_state restart-done
  stop_oi3_multi "$phase_dir/restart" 2>/dev/null || true
  stop_vpn
  capture_logs "$phase_dir/restart"
  write_phase_cleanup_log "$phase_dir/cleanup.log" "$phase_dir" "$phase_dir/restart"
  finalize_phase "$phase" "$phase_dir" epoch
}

cleanup() {
  local rc=$?
  if [[ "$WIFI_WAS_DISABLED" == 1 ]]; then
    adb_cmd shell svc wifi enable >/dev/null 2>&1 || true
    WIFI_WAS_DISABLED=0
    sleep 5
  fi
  stop_vpn || true
  stop_fixture || true
  if [[ "$PHASE_FAILURES" != 0 && "$rc" == 0 ]]; then rc=1; fi
  return "$rc"
}
trap cleanup EXIT

echo "# S153 E1 state/lifecycle companion"
echo "run_id=$RUN_ID device=$(adb_target_desc) package=$PACKAGE host=$HOST udp=$UDP_PORT tcp=$TCP_PORT"
echo "udpExpectEcho=$UDP_EXPECT_ECHO"
echo "artifact=$APK apk_sha256=$(sha256sum "$APK" | awk '{print $1}')"
device_preflight
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }
PACKAGE_UID="$(package_uid)"
[[ -n "$PACKAGE_UID" ]] || { echo "package UID unavailable" >&2; exit 1; }
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
start_fixture
printf 'phase,status,cleanup_pass,cleanup_fail,residual_vpp,tun0_after,rules_match\n' >"$CSV"

run_normal_restart
run_foreground_state screen-off screen-off
run_foreground_state forced-doze doze
run_fault_restart
run_epoch_restart

fixture_rx="$(grep -c ' RX ' "$FIXTURE_LOG" 2>/dev/null || true)"
fixture_tx="$(grep -c ' TX ' "$FIXTURE_LOG" 2>/dev/null || true)"
cat >"$MANIFEST" <<EOF
{
  "schema":"s153-e1-state-lifecycle/v1",
  "runId":"$RUN_ID",
  "package":"$PACKAGE",
  "device":"$(adb_target_desc)",
  "apkSha256":"$(sha256sum "$APK" | awk '{print $1}')",
  "pluginSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev_external_driver_poc_plugin.so | sha256sum | awk '{print $1}')",
  "hevSha256":"$(unzip -p "$APK" lib/arm64-v8a/libhev-socks5-tunnel.so | sha256sum | awk '{print $1}')",
  "udpPort":$UDP_PORT,
  "tcpPort":$TCP_PORT,
  "udpExpectEcho":$UDP_EXPECT_ECHO,
  "fixtureRx":$fixture_rx,
  "fixtureTx":$fixture_tx,
  "phaseFailures":$PHASE_FAILURES
}
EOF
echo "csv=$CSV"
echo "manifest=$MANIFEST"
echo "fixture=$fixture_rx/$fixture_tx"
echo "phase_failures=$PHASE_FAILURES"
[[ "$PHASE_FAILURES" == 0 ]]
