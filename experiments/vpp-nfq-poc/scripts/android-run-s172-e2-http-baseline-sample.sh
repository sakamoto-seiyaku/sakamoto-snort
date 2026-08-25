#!/usr/bin/env bash
set -euo pipefail

# S172 / E2 bounded matched HTTP baseline sample.
#
# Scope:
#   - same Android app-side HTTP stream probe
#   - same WSL2/LAN HTTP fixture endpoint
#   - direct, legacy HEV/tun-poc baseline, and final-topology OI3 arms
#
# This is a construction/health slice for the ADR-0007 E2 comparison matrix.
# It is not a full E2 verdict.  The HEV arm intentionally requires an explicit
# comparison APK that carries tun_poc_plugin alongside the OI3 plugin.  The
# canonical OI3 APK may omit tun_poc; do not reinterpret that as an OI3
# datapath failure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
HOST="${HOST:-192.168.4.5}"
FIXTURE_BIND="${FIXTURE_BIND:-0.0.0.0}"
HTTP_PORT="${HTTP_PORT:-42187}"
HTTP_PATH_PREFIX="${HTTP_PATH_PREFIX:-/s172}"
DURATION_SECONDS="${DURATION_SECONDS:-10}"
MAX_REQUESTS="${MAX_REQUESTS:-1}"
REQUEST_INTERVAL_MS="${REQUEST_INTERVAL_MS:-0}"
REPEATS="${REPEATS:-1}"
ARMS="${ARMS:-direct hev oi3}"
DEVICE_STATE="${DEVICE_STATE:-foreground}"
STATE_APPLY_DELAY_SECONDS="${STATE_APPLY_DELAY_SECONDS:-1}"
STATE_SETTLE_SECONDS="${STATE_SETTLE_SECONDS:-3}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s172-e2-http-baseline-sample-20260825}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT_EXTRA="${PROBE_WAIT_EXTRA:-5}"
STOP_WAIT="${STOP_WAIT:-3}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SOCKS_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server-s172.log"

ADB="${ADB:-$REPO_ROOT/dev/adb}"
ADB_LIB_READY=0

mkdir -p "$RESULT_DIR"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
CELL_ROOT="$RESULT_DIR/cells/$RUN_ID"
mkdir -p "$CELL_ROOT"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
CSV="$RESULT_DIR/cells-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
VALIDITY="$RESULT_DIR/run-validity-$RUN_ID.txt"
FIXTURE_LOG="$RESULT_DIR/fixture-$RUN_ID.log"
FIXTURE_SCRIPT="$RESULT_DIR/fixture-$RUN_ID.py"

REMOTE_FILES="/data/user/0/$PACKAGE/files"
REMOTE_APP_HTTP_LOG="$REMOTE_FILES/logs/app-http-probe.log"
REMOTE_LOGS="$REMOTE_FILES/vpp/logs"
REMOTE_CLI_LOG="$REMOTE_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$REMOTE_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$REMOTE_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$REMOTE_LOGS/vpp-protect.log"

exec > >(tee "$RUN_LOG") 2>&1

FIXTURE_PID=""

has_arm() {
  local wanted="$1" arm
  for arm in $ARMS; do
    [[ "$arm" == "$wanted" ]] && return 0
  done
  return 1
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

require_any_apk_member() {
  local reason="$1" member
  shift
  for member in "$@"; do
    if apk_has_member "$member"; then
      printf '%s\n' "$member"
      return 0
    fi
  done
  echo "preflight=FAIL missing_any_apk_member=$* reason=$reason" >&2
  return 1
}

preflight_apk() {
  [[ -f "$APK" ]] || { echo "preflight=FAIL missing_apk=$APK" >&2; return 1; }
  require_apk_member "lib/arm64-v8a/libhev_external_driver_poc_plugin.so" \
    "oi3-final-topology"
  require_apk_member "lib/arm64-v8a/libhev-socks5-tunnel.so" \
    "oi3-owner-context-and-hev-baseline"
  if has_arm hev; then
    require_any_apk_member "hev-baseline-tun-poc" \
      "lib/arm64-v8a/libtun_poc_plugin.so" \
      "lib/arm64-v8a/tun_poc_plugin.so" >/dev/null
  fi
}

start_fixture() {
  cat >"$FIXTURE_SCRIPT" <<'PY'
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

bind = sys.argv[1]
port = int(sys.argv[2])

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = (f"s172 ok path={self.path} time={time.time():.6f}\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"{time.time():.6f} HTTP GET client={self.client_address[0]}:{self.client_address[1]} path={self.path} bytes={len(body)}", flush=True)

    def log_message(self, fmt, *args):
        return

server = ThreadingHTTPServer((bind, port), Handler)
print(f"fixture listening http={bind}:{port}", flush=True)
server.serve_forever()
PY
  python3 -u "$FIXTURE_SCRIPT" "$FIXTURE_BIND" "$HTTP_PORT" >"$FIXTURE_LOG" 2>&1 &
  FIXTURE_PID="$!"
  for _ in $(seq 1 40); do
    if rg -q "fixture listening" "$FIXTURE_LOG" 2>/dev/null; then
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

start_socks_server() {
  "$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
  adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$SOCKS_LOG' '$REMOTE_ROOT/runtime/socks-s172.pid'"
  adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
  adb_su "chmod 755 '$REMOTE_SERVER'; nohup '$REMOTE_SERVER' >'$SOCKS_LOG' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/socks-s172.pid'"
  sleep 1
  adb_su "cat '$REMOTE_ROOT/runtime/socks-s172.pid'; cat '$SOCKS_LOG' 2>/dev/null || true" \
    | tr -d '\r' >"$RESULT_DIR/socks-server-$RUN_ID-start.log"
}

stop_socks_server() {
  adb_su "if [ -f '$REMOTE_ROOT/runtime/socks-s172.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/socks-s172.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/socks-s172.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/socks-s172.pid'" \
    >/dev/null 2>&1 || true
}

adb_read() {
  adb_su "$1" | tr -d '\r'
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
    adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
    adb_cmd shell input keyevent 224 >/dev/null 2>&1 || true
    stop_vpn
    if has_arm hev; then
      stop_socks_server
    fi
  fi
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

capture_device_state() {
  local label="$1" output="$2"
  {
    echo "state=$label"
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

prepare_device_state() {
  adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  adb_cmd shell input keyevent 224 >/dev/null 2>&1 || true
  sleep 1
}

apply_device_state() {
  local cell="$1"
  case "$DEVICE_STATE" in
    foreground)
      capture_device_state foreground "$cell/state-foreground.txt"
      ;;
    screen-off)
      sleep "$STATE_APPLY_DELAY_SECONDS"
      adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
      sleep "$STATE_SETTLE_SECONDS"
      capture_device_state screen-off "$cell/state-screen-off.txt"
      ;;
    forced-doze)
      sleep "$STATE_APPLY_DELAY_SECONDS"
      adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
      sleep 1
      adb_cmd shell dumpsys deviceidle force-idle >"$cell/force-idle-command.txt" 2>&1 || true
      sleep "$STATE_SETTLE_SECONDS"
      capture_device_state forced-doze "$cell/state-forced-doze.txt"
      ;;
    *)
      echo "invalid DEVICE_STATE=$DEVICE_STATE" >&2
      return 1
      ;;
  esac
}

recover_device_state() {
  local cell="$1"
  adb_cmd shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  adb_cmd shell input keyevent 224 >/dev/null 2>&1 || true
  sleep 2
  capture_device_state wake "$cell/state-wake.txt"
}

device_state_valid() {
  local cell="$1"
  case "$DEVICE_STATE" in
    foreground)
      return 0
      ;;
    screen-off)
      rg -q 'mScreenOn=false|mInteractive=false|mWakefulness=Asleep|mWakefulness=Dozing' \
        "$cell/state-screen-off.txt"
      ;;
    forced-doze)
      rg -q 'mState=IDLE|mState=IDLE_MAINTENANCE' "$cell/state-forced-doze.txt"
      ;;
    *)
      return 1
      ;;
  esac
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

cpu_ticks_from_resource() {
  local file="$1" label="$2"
  awk -v label="$label" '
    $0 ~ "^--- " label " stat pid=" {
      getline
      if ($13 ~ /^[0-9]+$/ && $14 ~ /^[0-9]+$/) {
        print $13 + $14
      }
      exit
    }
  ' "$file"
}

sched_runtime_ns_from_resource() {
  local file="$1" label="$2"
  awk -v label="$label" '
    $0 ~ "^--- " label " schedstat" {
      getline
      if ($1 ~ /^[0-9]+$/) {
        print $1
      }
      exit
    }
  ' "$file"
}

numeric_delta() {
  local after="${1:-0}" before="${2:-0}"
  awk -v after="${after:-0}" -v before="${before:-0}" 'BEGIN {print (after + 0) - (before + 0)}'
}

kv_from_stream_done() {
  local key="$1" file="$2"
  awk -v key="$key" '
    /stream-done / {
      for (i = 1; i <= NF; i++) {
        if (index($i, key "=") == 1) {
          sub("^" key "=", "", $i)
          print $i
        }
      }
    }
  ' "$file" | tail -n 1
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

wait_vpp_hev_ready() {
  local vpp_pid="" tun_poc_line=""
  for _ in $(seq 1 120); do
    vpp_pid="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")"
    tun_poc_line="$(adb_read "grep -E 'tun-poc enabled|tun-poc mode|show tun-poc' '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null | tail -n 12")"
    if [[ -n "$vpp_pid" && -n "$tun_poc_line" ]]; then
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

run_http_probe() {
  local path="$1"
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez appHttpProbe true \
    --es host "$HOST" --ei port "$HTTP_PORT" --es path "$path" \
    --ei durationSeconds "$DURATION_SECONDS" --ei count "$MAX_REQUESTS" \
    --ei requestIntervalMs "$REQUEST_INTERVAL_MS" >/dev/null
}

wait_http_done() {
  local output="$1" timeout=$((DURATION_SECONDS + PROBE_WAIT_EXTRA + 15))
  local app_log=""
  for _ in $(seq 1 "$timeout"); do
    app_log="$(adb_read "cat '$REMOTE_APP_HTTP_LOG' 2>/dev/null || true")"
    if rg -q 'stream-done ' <<<"$app_log"; then
      printf '%s\n' "$app_log" >"$output"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$app_log" >"$output"
  return 1
}

fixture_count() {
  local pattern="$1"
  count_matches "$pattern" "$FIXTURE_LOG"
}

count_matches() {
  local pattern="$1" file="$2" count
  count="$(rg -c "$pattern" "$file" 2>/dev/null || true)"
  printf '%s\n' "${count:-0}"
}

write_validity() {
  local uid="$1" installed_path native_dir tun_member
  installed_path="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/base.apk#p' | head -n 1")"
  native_dir="$(adb_read "pm path '$PACKAGE' | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1")"
  tun_member="$(require_any_apk_member "optional-report" \
    "lib/arm64-v8a/libtun_poc_plugin.so" "lib/arm64-v8a/tun_poc_plugin.so" 2>/dev/null || true)"
  {
    echo "schema=s172-e2-http-baseline-sample/v1"
    echo "scope=bounded_matched_http_baseline_not_full_e2"
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(adb_target_desc)"
    echo "device_model=$(adb_read 'getprop ro.product.model')"
    echo "device_fingerprint=$(adb_read 'getprop ro.build.fingerprint')"
    echo "android_release=$(adb_read 'getprop ro.build.version.release')"
    echo "package=$PACKAGE package_uid=$uid"
    echo "arms=$ARMS repeats=$REPEATS durationSeconds=$DURATION_SECONDS maxRequests=$MAX_REQUESTS requestIntervalMs=$REQUEST_INTERVAL_MS"
    echo "deviceState=$DEVICE_STATE stateApplyDelaySeconds=$STATE_APPLY_DELAY_SECONDS stateSettleSeconds=$STATE_SETTLE_SECONDS"
    echo "host=$HOST fixture_bind=$FIXTURE_BIND http_port=$HTTP_PORT"
    echo "apk_host=$APK"
    echo "apk_sha256=$(sha256sum "$APK" | awk '{print $1}')"
    echo "apk_oi3_plugin_sha256=$(sha256_apk_member 'lib/arm64-v8a/libhev_external_driver_poc_plugin.so')"
    echo "apk_hev_sha256=$(sha256_apk_member 'lib/arm64-v8a/libhev-socks5-tunnel.so')"
    echo "apk_tun_poc_member=$tun_member"
    [[ -n "$tun_member" ]] && echo "apk_tun_poc_sha256=$(sha256_apk_member "$tun_member")"
    echo "installed_apk_path=$installed_path"
    echo "installed_apk_sha256=$(adb_read "sha256sum '$installed_path'")"
    echo "device_native_dir=$native_dir"
    echo "device_oi3_plugin_sha256=$(adb_read "sha256sum '$native_dir/libhev_external_driver_poc_plugin.so' 2>/dev/null || true")"
    echo "device_hev_sha256=$(adb_read "sha256sum '$native_dir/libhev-socks5-tunnel.so' 2>/dev/null || true")"
    echo "device_tun_poc_sha256=$(adb_read "sha256sum '$native_dir/libtun_poc_plugin.so' '$native_dir/tun_poc_plugin.so' 2>/dev/null || true")"
    echo "fixture_log=$FIXTURE_LOG"
    echo "--- package state ---"
    adb_read "dumpsys package '$PACKAGE' 2>/dev/null || true" \
      | rg 'userId=|requested permissions:|android.permission\.(INTERNET|NEARBY_WIFI_DEVICES)|RESTRICT_LOCAL_NETWORK' \
      || true
    echo "--- networks ---"
    adb_read 'dumpsys connectivity 2>/dev/null || true' \
      | rg 'NetworkAgentInfo|TRANSPORT_VPN|NOT_VPN|WIFI|network\{netId' \
      | head -n 120 \
      || true
    echo "--- git ---"
    echo "git_revision=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  } >"$VALIDITY"
}

run_cell() {
  local arm="$1" repeat="$2"
  local label="$arm-r$repeat"
  local cell="$CELL_ROOT/$label"
  local start_rc=0 start_output="" probe_ok=1 startup_valid=1 vpp_ready=""
  local path="$HTTP_PATH_PREFIX/$label"
  local baseline_rules after_rules snapshot_before snapshot_steady snapshot_after snapshot_stop
  mkdir -p "$cell"
  echo "## cell=$label"

  prepare_device_state
  stop_vpn
  adb_read "rm -f '$REMOTE_APP_HTTP_LOG' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG'"
  baseline_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$baseline_rules" >"$cell/baseline-ip-rules.txt"

  case "$arm" in
    direct)
      ;;
    hev)
      set +e
      start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
        --ez start true --es mode vpp-hev 2>&1)"
      start_rc=$?
      set -e
      printf '%s\n' "$start_output" >"$cell/start.txt"
      vpp_ready="$(wait_vpp_hev_ready || true)"
      [[ "$start_rc" == 0 && -n "$vpp_ready" ]] || startup_valid=0
      ;;
    oi3)
      set +e
      start_output="$(adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" \
        --ez start true --es mode vpp-oi3-multi --es allowedPackage "$PACKAGE" 2>&1)"
      start_rc=$?
      set -e
      printf '%s\n' "$start_output" >"$cell/start.txt"
      vpp_ready="$(wait_vpp_oi3_ready || true)"
      [[ "$start_rc" == 0 && -n "$vpp_ready" ]] || startup_valid=0
      ;;
    *)
      echo "unknown arm=$arm" >&2
      return 1
      ;;
  esac

  if [[ "$startup_valid" != 1 ]]; then
    adb_read "cat '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$cell/startup-logs.txt"
  else
    sleep "$START_WAIT"
    snapshot_before="$(process_snapshot)"
    printf '%s\n' "$snapshot_before" >"$cell/processes-before.txt"
    capture_resource before "$snapshot_before" "$uid" "$cell/resource-before.raw"
    run_http_probe "$path"
    apply_device_state "$cell"
    sleep "$DURATION_SECONDS"
    snapshot_steady="$(process_snapshot)"
    printf '%s\n' "$snapshot_steady" >"$cell/processes-steady.txt"
    capture_resource steady "$snapshot_steady" "$uid" "$cell/resource-steady.raw"
    wait_http_done "$cell/app-http-probe.log" || probe_ok=0
    snapshot_after="$(process_snapshot)"
    printf '%s\n' "$snapshot_after" >"$cell/processes-after-probe.txt"
    capture_resource after-probe "$snapshot_after" "$uid" "$cell/resource-after-probe.raw"
  fi

  adb_read "cat '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$cell/vpp-cli.log"
  adb_read "cat '$REMOTE_STDOUT_LOG' 2>/dev/null || true" >"$cell/vpp-stdout.log"
  adb_read "cat '$REMOTE_HEV_LOG' 2>/dev/null || true" >"$cell/vpp-hev.log"
  adb_read "cat '$REMOTE_PROTECT_LOG' 2>/dev/null || true" >"$cell/vpp-protect.log"
  if [[ "$arm" == hev ]]; then
    adb_read "cat '$SOCKS_LOG' 2>/dev/null || true" >"$cell/socks.log"
  fi
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r' >"$cell/logcat.txt"

  if [[ "$arm" == oi3 ]]; then
    run_oi3_control "multi-stop" "$cell/oi3-control-multi-stop.txt" || true
    wait_oi3_cleanup "$cell/cleanup-pre-stop.log" || true
  fi
  stop_vpn
  recover_device_state "$cell"
  snapshot_stop="$(process_snapshot)"
  printf '%s\n' "$snapshot_stop" >"$cell/processes-after-stop.txt"
  adb_read "cat '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' 2>/dev/null || true" >"$cell/cleanup.log"
  after_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$after_rules" >"$cell/after-ip-rules.txt"

  requests="$(kv_from_stream_done requests "$cell/app-http-probe.log" || true)"
  successes="$(kv_from_stream_done successes "$cell/app-http-probe.log" || true)"
  errors="$(kv_from_stream_done errors "$cell/app-http-probe.log" || true)"
  request_bytes="$(kv_from_stream_done requestBytes "$cell/app-http-probe.log" || true)"
  response_bytes="$(kv_from_stream_done responseBytes "$cell/app-http-probe.log" || true)"
  elapsed_ms="$(kv_from_stream_done elapsedMs "$cell/app-http-probe.log" || true)"
  p50="$(kv_from_stream_done latencyMsP50 "$cell/app-http-probe.log" || true)"
  p95="$(kv_from_stream_done latencyMsP95 "$cell/app-http-probe.log" || true)"
  p99="$(kv_from_stream_done latencyMsP99 "$cell/app-http-probe.log" || true)"
  read_timeout_after_bytes="$(kv_from_stream_done readTimeoutAfterBytes "$cell/app-http-probe.log" || true)"
  content_length_completions="$(kv_from_stream_done contentLengthCompletions "$cell/app-http-probe.log" || true)"
  cleanup_pass="$(count_matches 'oi3_cleanup result=PASS' "$cell/cleanup.log")"
  cleanup_fail="$(count_matches 'oi3_cleanup result=FAIL' "$cell/cleanup.log")"
  socks_connect_count=0
  if [[ "$arm" == hev ]]; then
    socks_connect_count="$(count_matches "connect $HOST:$HTTP_PORT" "$cell/socks.log")"
  fi
  app_rss="$(metric_from_resource "$cell/resource-steady.raw" app 2>/dev/null || true)"
  vpp_rss="$(metric_from_resource "$cell/resource-steady.raw" vpp 2>/dev/null || true)"
  hev_rss="$(metric_from_resource "$cell/resource-steady.raw" hev 2>/dev/null || true)"
  app_fd="$(fd_from_resource "$cell/resource-steady.raw" app 2>/dev/null || true)"
  vpp_fd="$(fd_from_resource "$cell/resource-steady.raw" vpp 2>/dev/null || true)"
  hev_fd="$(fd_from_resource "$cell/resource-steady.raw" hev 2>/dev/null || true)"
  app_threads="$(threads_from_resource "$cell/resource-steady.raw" app 2>/dev/null || true)"
  vpp_threads="$(threads_from_resource "$cell/resource-steady.raw" vpp 2>/dev/null || true)"
  hev_threads="$(threads_from_resource "$cell/resource-steady.raw" hev 2>/dev/null || true)"
  app_cpu_before="$(cpu_ticks_from_resource "$cell/resource-before.raw" app 2>/dev/null || true)"
  app_cpu_after="$(cpu_ticks_from_resource "$cell/resource-after-probe.raw" app 2>/dev/null || true)"
  vpp_cpu_before="$(cpu_ticks_from_resource "$cell/resource-before.raw" vpp 2>/dev/null || true)"
  vpp_cpu_after="$(cpu_ticks_from_resource "$cell/resource-after-probe.raw" vpp 2>/dev/null || true)"
  hev_cpu_before="$(cpu_ticks_from_resource "$cell/resource-before.raw" hev 2>/dev/null || true)"
  hev_cpu_after="$(cpu_ticks_from_resource "$cell/resource-after-probe.raw" hev 2>/dev/null || true)"
  app_cpu_delta="$(numeric_delta "${app_cpu_after:-0}" "${app_cpu_before:-0}")"
  vpp_cpu_delta="$(numeric_delta "${vpp_cpu_after:-0}" "${vpp_cpu_before:-0}")"
  hev_cpu_delta="$(numeric_delta "${hev_cpu_after:-0}" "${hev_cpu_before:-0}")"
  total_cpu_delta="$(awk -v app="$app_cpu_delta" -v vpp="$vpp_cpu_delta" -v hev="$hev_cpu_delta" 'BEGIN {print app + vpp + hev}')"
  app_sched_before="$(sched_runtime_ns_from_resource "$cell/resource-before.raw" app 2>/dev/null || true)"
  app_sched_after="$(sched_runtime_ns_from_resource "$cell/resource-after-probe.raw" app 2>/dev/null || true)"
  vpp_sched_before="$(sched_runtime_ns_from_resource "$cell/resource-before.raw" vpp 2>/dev/null || true)"
  vpp_sched_after="$(sched_runtime_ns_from_resource "$cell/resource-after-probe.raw" vpp 2>/dev/null || true)"
  hev_sched_before="$(sched_runtime_ns_from_resource "$cell/resource-before.raw" hev 2>/dev/null || true)"
  hev_sched_after="$(sched_runtime_ns_from_resource "$cell/resource-after-probe.raw" hev 2>/dev/null || true)"
  app_sched_delta="$(numeric_delta "${app_sched_after:-0}" "${app_sched_before:-0}")"
  vpp_sched_delta="$(numeric_delta "${vpp_sched_after:-0}" "${vpp_sched_before:-0}")"
  hev_sched_delta="$(numeric_delta "${hev_sched_after:-0}" "${hev_sched_before:-0}")"
  total_sched_delta="$(awk -v app="$app_sched_delta" -v vpp="$vpp_sched_delta" -v hev="$hev_sched_delta" 'BEGIN {print app + vpp + hev}')"
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null || true")"
  tun0_after=0
  adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0_after=1 || true
  rules_match=0
  [[ "$baseline_rules" == "$after_rules" ]] && rules_match=1
  state_valid=1
  device_state_valid "$cell" || state_valid=0

  valid=1
  [[ "$startup_valid" == 1 && "$probe_ok" == 1 ]] || valid=0
  [[ "${requests:-0}" != 0 && "${successes:-0}" == "${requests:-0}" ]] || valid=0
  [[ "${errors:-999}" == 0 && "${response_bytes:-0}" != 0 ]] || valid=0
  [[ "${content_length_completions:-0}" == "${successes:-0}" ]] || valid=0
  if [[ "$arm" == hev ]]; then
    [[ "$socks_connect_count" -gt 0 ]] || valid=0
  fi
  if [[ "$arm" == oi3 ]]; then
    [[ "$cleanup_fail" == 0 && "$cleanup_pass" -gt 0 ]] || valid=0
  fi
  [[ -z "$residual_vpp" && "$tun0_after" == 0 && "$rules_match" == 1 && "$state_valid" == 1 ]] || valid=0

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$label" "$arm" "$repeat" "$DEVICE_STATE" "$state_valid" "$startup_valid" "${requests:-0}" "${successes:-0}" \
    "${errors:-999}" "${request_bytes:-0}" "${response_bytes:-0}" "${elapsed_ms:-0}" \
    "${p50:-0}" "${p95:-0}" "${p99:-0}" "${read_timeout_after_bytes:-0}" \
    "${content_length_completions:-0}" "$socks_connect_count" \
    "${app_rss:-0}" "${vpp_rss:-0}" "${hev_rss:-0}" \
    "${app_fd:-0}" "${vpp_fd:-0}" "${hev_fd:-0}" \
    "${app_threads:-0}" "${vpp_threads:-0}" "${hev_threads:-0}" \
    "${app_cpu_delta:-0}" "${vpp_cpu_delta:-0}" "${hev_cpu_delta:-0}" "${total_cpu_delta:-0}" \
    "${app_sched_delta:-0}" "${vpp_sched_delta:-0}" "${hev_sched_delta:-0}" "${total_sched_delta:-0}" \
    "$cleanup_pass" \
    "$cleanup_fail" "$rules_match" "$valid" >>"$CSV"

  echo "cell=$label valid=$valid startup=$startup_valid state=$DEVICE_STATE stateValid=$state_valid requests=${requests:-0} successes=${successes:-0} errors=${errors:-999} p50=${p50:-0} p95=${p95:-0} p99=${p99:-0} cpuTicksDelta=${total_cpu_delta:-0} schedRuntimeNsDelta=${total_sched_delta:-0} readTimeoutAfterBytes=${read_timeout_after_bytes:-0} contentLengthCompletions=${content_length_completions:-0} socksConnect=$socks_connect_count cleanup=$cleanup_pass/$cleanup_fail"
  [[ "$valid" == 1 ]]
}

echo "# S172 E2 bounded matched HTTP baseline sample"
echo "run_id=$RUN_ID"
echo "package=$PACKAGE host=$HOST port=$HTTP_PORT arms=$ARMS repeats=$REPEATS durationSeconds=$DURATION_SECONDS maxRequests=$MAX_REQUESTS requestIntervalMs=$REQUEST_INTERVAL_MS deviceState=$DEVICE_STATE"
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
echo "fixture=start"
start_fixture
echo "fixture=ready"
if has_arm hev; then
  echo "socks=start"
  start_socks_server
  echo "socks=ready"
fi

printf 'label,arm,repeat,deviceState,stateValid,startupValid,requests,successes,errors,requestBytes,responseBytes,elapsedMs,latencyMsP50,latencyMsP95,latencyMsP99,readTimeoutAfterBytes,contentLengthCompletions,socksConnectCount,appRssKb,vppRssKb,hevRssKb,appFd,vppFd,hevFd,appThreads,vppThreads,hevThreads,appCpuTicksDelta,vppCpuTicksDelta,hevCpuTicksDelta,totalCpuTicksDelta,appSchedRuntimeNsDelta,vppSchedRuntimeNsDelta,hevSchedRuntimeNsDelta,totalSchedRuntimeNsDelta,cleanupPass,cleanupFail,rulesMatch,valid\n' >"$CSV"

failures=0
for repeat in $(seq 1 "$REPEATS"); do
  for arm in $ARMS; do
    if ! run_cell "$arm" "$repeat"; then
      failures=$((failures + 1))
    fi
  done
done

fixture_http_get="$(fixture_count 'HTTP GET')"
cat >"$MANIFEST" <<EOF
{
  "schema":"s172-e2-http-baseline-sample/v1",
  "scope":"bounded_matched_http_baseline_not_full_e2",
  "runId":"$RUN_ID",
  "package":"$PACKAGE",
  "endpoint":"$HOST",
  "fixtureBind":"$FIXTURE_BIND",
  "httpPort":$HTTP_PORT,
  "arms":"$ARMS",
  "repeats":$REPEATS,
  "durationSeconds":$DURATION_SECONDS,
  "maxRequests":$MAX_REQUESTS,
  "requestIntervalMs":$REQUEST_INTERVAL_MS,
  "deviceState":"$DEVICE_STATE",
  "stateApplyDelaySeconds":$STATE_APPLY_DELAY_SECONDS,
  "stateSettleSeconds":$STATE_SETTLE_SECONDS,
  "cellRoot":"$CELL_ROOT",
  "apkSha256":"$(sha256sum "$APK" | awk '{print $1}')",
  "oi3PluginSha256":"$(sha256_apk_member 'lib/arm64-v8a/libhev_external_driver_poc_plugin.so')",
  "hevSha256":"$(sha256_apk_member 'lib/arm64-v8a/libhev-socks5-tunnel.so')",
  "tunPocPluginSha256":"$(sha256_apk_member 'lib/arm64-v8a/libtun_poc_plugin.so' || sha256_apk_member 'lib/arm64-v8a/tun_poc_plugin.so' || true)",
  "fixtureHttpGet":$fixture_http_get,
  "failureCount":$failures
}
EOF

echo "results=$RESULT_DIR"
echo "csv=$CSV"
echo "manifest=$MANIFEST"
echo "validity=$VALIDITY"
echo "failures=$failures"
[[ "$failures" == 0 ]]
