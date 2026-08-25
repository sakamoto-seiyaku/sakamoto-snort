#!/usr/bin/env bash
set -euo pipefail

# S125 / POC-7 real-device runner.  It records raw observations and emits a
# machine-readable summary; the copy-investment decision remains a separate
# review step in S125_COPY_INVESTMENT_MEMO.md.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s125/$(date +%Y%m%d-%H%M%S)-pixel6a-poc7}"
REMOTE_APP_FILES="${REMOTE_APP_FILES:-/data/user/0/$PACKAGE/files}"
REMOTE_RESULT_ROOT="${REMOTE_RESULT_ROOT:-/data/local/tmp/s125-poc7}"
WARMUP_SECONDS="${WARMUP_SECONDS:-10}"
STEADY_SECONDS="${STEADY_SECONDS:-30}"
DRAIN_SECONDS="${DRAIN_SECONDS:-10}"
RECONNECT_EVERY="${RECONNECT_EVERY:-}"
UDP_SOURCE_PORT_BASE="${UDP_SOURCE_PORT_BASE:-43000}"
TCP_SOURCE_PORT_BASE="${TCP_SOURCE_PORT_BASE:-44000}"
UDP_CLOSED_TIMEOUT_MS="${UDP_CLOSED_TIMEOUT_MS:-1000}"
UDP_SATURATING_TIMEOUT_MS="${UDP_SATURATING_TIMEOUT_MS:-200}"
REPEATS="${REPEATS:-3}"
TIER="${TIER:-0}"
SIMPLEPERF="${SIMPLEPERF:-0}"
SIMPLEPERF_DURATION="${SIMPLEPERF_DURATION:-20}"
SIMPLEPERF_HOST="${SIMPLEPERF_HOST:-/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf/bin/android/arm64/simpleperf}"
SIMPLEPERF_REMOTE="${SIMPLEPERF_REMOTE:-/data/local/tmp/simpleperf-s125}"
SIMPLEPERF_WAIT_SECONDS="${SIMPLEPERF_WAIT_SECONDS:-90}"
THERMAL_GUARD_EVERY="${THERMAL_GUARD_EVERY:-6}"
THERMAL_GUARD_COOLDOWN_SECONDS="${THERMAL_GUARD_COOLDOWN_SECONDS:-20}"
THERMAL_MAX_MILLIC="${THERMAL_MAX_MILLIC:-65000}"
VPN_RESTART_SETTLE_SECONDS="${VPN_RESTART_SETTLE_SECONDS:-3}"
VPN_READY_SETTLE_SECONDS="${VPN_READY_SETTLE_SECONDS:-3}"
PAIR_OBSERVE_SEQUENCE="${PAIR_OBSERVE_SEQUENCE:-}"
PAIR_OBSERVE_INTERVAL_SECONDS="${PAIR_OBSERVE_INTERVAL_SECONDS:-10}"
PAIR_OBSERVE_SHOW_COMMAND="${PAIR_OBSERVE_SHOW_COMMAND:-show s124-vpn-tun-lite}"
RUNNER_VERSION="s125-poc7/v5"
CELL_COUNT=0
TCP_COPY_CALIBRATE="${TCP_COPY_CALIBRATE:-1}"
TCP_HANDSHAKE_GATE="${TCP_HANDSHAKE_GATE:-1}"
TCP_GATE_WARMUP_SECONDS="${TCP_GATE_WARMUP_SECONDS:-1}"
TCP_GATE_STEADY_SECONDS="${TCP_GATE_STEADY_SECONDS:-3}"
TCP_GATE_DRAIN_SECONDS="${TCP_GATE_DRAIN_SECONDS:-3}"
TCP_HANDSHAKE_GATE_RESULT="not-run"

validate_source_port_base() {
  local value="$1" name="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be numeric: $value" >&2
    exit 2
  fi
  if (( value < 1024 || value > 65503 )); then
    echo "$name must be in 1024..65503 for the max 32-flow probe: $value" >&2
    exit 2
  fi
}

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
validate_source_port_base "$UDP_SOURCE_PORT_BASE" UDP_SOURCE_PORT_BASE
validate_source_port_base "$TCP_SOURCE_PORT_BASE" TCP_SOURCE_PORT_BASE
device_preflight
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 1; }

sha256_optional() {
  local path="${1:-}"
  [[ -n "$path" && -f "$path" ]] || return 0
  sha256sum "$path" | awk '{print $1}'
}

sha256_apk_member() {
  local member="$1"
  unzip -p "$APK" "$member" 2>/dev/null | sha256sum | awk '{print $1}'
}

DEVICE_SERIAL="$(adb_target_desc)"
DEVICE_MODEL="$(adb_su 'getprop ro.product.model' | tr -d '\r\n')"
DEVICE_FINGERPRINT="$(adb_su 'getprop ro.build.fingerprint' | tr -d '\r\n')"
DEVICE_RELEASE="$(adb_su 'getprop ro.build.version.release' | tr -d '\r\n')"
APK_SHA256="$(sha256sum "$APK" | awk '{print $1}')"
VPP_PLUGIN_SHA256="$(sha256_optional "${VPP_PLUGIN_HOST:-}")"
HEV_LIB_SHA256="$(sha256_optional "${HEV_LIB_HOST:-}")"
RUNNER_GIT_REV="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"

if [[ "${INSTALL_APK:-1}" == 1 ]]; then
  adb_cmd install -r "$APK" >/dev/null
fi
if [[ "$SIMPLEPERF" == 1 ]]; then
  [[ -x "$SIMPLEPERF_HOST" ]] || { echo "simpleperf not found: $SIMPLEPERF_HOST" >&2; exit 1; }
  adb_cmd push "$SIMPLEPERF_HOST" "$SIMPLEPERF_REMOTE" >/dev/null
  adb_su "chmod 755 '$SIMPLEPERF_REMOTE'"
fi

REMOTE_VPP_RUNTIME="$REMOTE_APP_FILES/vpp/runtime"
REMOTE_VPP_LOGS="$REMOTE_APP_FILES/vpp/logs"
REMOTE_APP_LOG="$REMOTE_APP_FILES/logs/app-l4-stress-probe.log"
REMOTE_CLI_LOG="$REMOTE_VPP_LOGS/vpp-cli.log"

vpp_pid_from_log() {
  adb_su "grep -m1 'vpp monitor start pid=' '$REMOTE_CLI_LOG' 2>/dev/null || true" \
    | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1
}

wait_vpp_ready() {
  local pid=""
  for _ in $(seq 1 120); do
    if adb_su "test -S '$REMOTE_VPP_RUNTIME/cli.sock'" >/dev/null 2>&1; then
      pid="$(vpp_pid_from_log)"
      [[ -n "$pid" ]] && { printf '%s\n' "$pid"; return 0; }
    fi
    sleep 0.25
  done
  return 1
}

wait_poc7_registered() {
  # The monitor emits a real ``show s124-vpn-tun`` snapshot only after the
  # plugin's CLI constructor and startup ``enable`` command both succeeded.
  # Do not start the traffic generator until that evidence exists; otherwise
  # an unloaded/mismatched plugin becomes a misleading zero-throughput cell.
  for _ in $(seq 1 180); do
    if adb_su "grep -Fq 's124-vpn-tun-stage ' '$REMOTE_CLI_LOG' 2>/dev/null"; then
      return 0
    fi
    if adb_su "grep -Eq 'unknown input .*s124-vpn-tun' '$REMOTE_CLI_LOG' 2>/dev/null"; then
      return 1
    fi
    sleep 0.25
  done
  return 1
}

vpp_native_dir() {
  adb_su "pm path '$PACKAGE' 2>/dev/null | sed -n 's#^package:\(.*\)/base.apk\$#\1/lib/arm64#p' | head -n 1" \
    | tr -d '\r\n'
}

run_vpp_cli() {
  local command="$1" native_dir
  native_dir="$(vpp_native_dir)"
  [[ -n "$native_dir" ]] || return 1
  adb_su "export LD_LIBRARY_PATH='$native_dir'; '$native_dir/libvppctl.so' -s '$REMOTE_VPP_RUNTIME/cli.sock' $command"
}

app_pid() {
  adb_su "pidof '$PACKAGE' 2>/dev/null | tr ' ' '\\n' | head -n 1" | tr -d '\r\n'
}

collect_resource() {
  local phase="$1" vpp_pid="$2" output="$3" app="$(app_pid || true)"
  {
    echo "phase=$phase"
    echo "host_time=$(date -Ins)"
    echo "device_time=$(adb_su 'date -Ins' | tr -d '\r')"
    echo "vpp_pid=$vpp_pid app_pid=$app"
    echo "--- vpp status ---"
    adb_su "cat '/proc/$vpp_pid/status' 2>/dev/null || true"
    echo "--- vpp stat ---"
    adb_su "cat '/proc/$vpp_pid/stat' 2>/dev/null || true"
    echo "--- vpp threads ---"
    adb_su "for t in /proc/$vpp_pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); voluntary=\$(grep '^voluntary_ctxt_switches:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); nonvoluntary=\$(grep '^nonvoluntary_ctxt_switches:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); printf '%s comm=%s cpu=%s allowed=%s voluntary=%s nonvoluntary=%s\\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\" \"\$voluntary\" \"\$nonvoluntary\"; done" | tr -d '\r'
    echo "--- app status ---"
    [[ -z "$app" ]] || adb_su "cat '/proc/$app/status' 2>/dev/null || true"
    echo "--- app stat ---"
    [[ -z "$app" ]] || adb_su "cat '/proc/$app/stat' 2>/dev/null || true"
    echo "--- thermal ---"
    adb_su "dumpsys thermalservice 2>/dev/null || true"
    adb_su "for z in /sys/class/thermal/thermal_zone*; do printf '%s=' \"\$z\"; cat \"\$z/temp\" 2>/dev/null || true; done"
    echo "--- cpu policy ---"
    adb_su "for p in /sys/devices/system/cpu/cpufreq/policy*; do printf '%s min=' \"\$p\"; cat \"\$p/scaling_min_freq\" 2>/dev/null || true; printf ' max='; cat \"\$p/scaling_max_freq\" 2>/dev/null || true; printf ' cur='; cat \"\$p/scaling_cur_freq\" 2>/dev/null || true; echo; done"
  } >"$output"
}

thermal_max_millic() {
  adb_su "for z in /sys/class/thermal/thermal_zone*; do cat \"\$z/temp\" 2>/dev/null || true; done" \
    | tr -d '\r' | awk '/^[0-9]+$/ { if ($1 > max) max = $1 } END { print max + 0 }'
}

thermal_guard() {
  local guard_id="$1"
  local raw="$RESULT_DIR/thermal-guard-${guard_id}.raw"
  local before after
  before="$(thermal_max_millic)"
  {
    echo "guard=$guard_id"
    echo "host_time=$(date -Ins)"
    echo "device_time=$(adb_su 'date -Ins' | tr -d '\r')"
    echo "max_millic_before=$before"
    adb_su 'dumpsys thermalservice 2>/dev/null || true'
  } >"$raw"
  if (( before > THERMAL_MAX_MILLIC )); then
    sleep "$THERMAL_GUARD_COOLDOWN_SECONDS"
    after="$(thermal_max_millic)"
    echo "max_millic_after=$after" >>"$raw"
    if (( after > THERMAL_MAX_MILLIC )); then
      echo "thermal_guard_failed=1" >>"$raw"
      return 1
    fi
  fi
  echo "thermal_guard_failed=0" >>"$raw"
}

start_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez start true \
    --es mode "$1" --es allowedPackage "$PACKAGE" --es s124Path "$2" \
    --es s124Observe "$3" >/dev/null
}

start_probe() {
  local protocol="$1" flows="$2" payload="$3" burst="$4" load="$5" echo="$6" port=49154 source_port_base="$UDP_SOURCE_PORT_BASE"
  [[ "$protocol" == tcp ]] && port=49155 && source_port_base="$TCP_SOURCE_PORT_BASE"
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez appL4StressProbe true \
    --es protocol "$protocol" --es host 10.0.0.1 --ei port "$port" --ei flows "$flows" \
    --ei sourcePortBase "$source_port_base" --ei payloadBytes "$payload" \
    --ei burst "$burst" --es load "$load" \
    --ei warmupSeconds "$WARMUP_SECONDS" --ei steadySeconds "$STEADY_SECONDS" \
    --ei drainSeconds "$DRAIN_SECONDS" --ei reconnectEvery "${RECONNECT_EVERY:-0}" \
    --ei udpClosedTimeoutMs "$UDP_CLOSED_TIMEOUT_MS" \
    --ei udpSaturatingTimeoutMs "$UDP_SATURATING_TIMEOUT_MS" \
    --ez expectEcho "$echo" >/dev/null
}

stop_vpn() {
  adb_cmd shell am start -W -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
}

wait_probe_done() {
  local timeout=$((WARMUP_SECONDS + STEADY_SECONDS + DRAIN_SECONDS + 90))
  local run_id=""
  for _ in $(seq 1 "$timeout"); do
    run_id="$(adb_su "sed -n 's/.* start .*runId=\\([0-9][0-9]*\\).*/\\1/p' '$REMOTE_APP_LOG' 2>/dev/null | tail -n 1" | tr -d '\r\n')"
    if [[ -n "$run_id" ]] && adb_su "grep -Eq '(done|fail).*runId=$run_id' '$REMOTE_APP_LOG' 2>/dev/null"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

pull_raw() {
  adb_su "cat '$1' 2>/dev/null || true" | tr -d '\r' >"$2"
}

pull_binary() {
  adb_su "cat '$1' 2>/dev/null || true" >"$2"
}

start_simpleperf() {
  local vpp_pid="$1" label="$2" data="$REMOTE_RESULT_ROOT/$label.data"
  local pidfile="$REMOTE_RESULT_ROOT/$label.pid"
  local logfile="$REMOTE_RESULT_ROOT/$label.simpleperf.log"
  adb_su "mkdir -p '$REMOTE_RESULT_ROOT'; rm -f '$data' '$pidfile' '$logfile'; \
    '$SIMPLEPERF_REMOTE' record -p '$vpp_pid' -g --duration '$SIMPLEPERF_DURATION' \
    -o '$data' >'$logfile' 2>&1 & echo \$! >'$pidfile'"
}

wait_simpleperf() {
  local label="$1" pidfile="$REMOTE_RESULT_ROOT/$label.pid"
  local data="$REMOTE_RESULT_ROOT/$label.data"
  local timeout="$SIMPLEPERF_WAIT_SECONDS"
  for _ in $(seq 1 "$timeout"); do
    if adb_su "test -s '$data' && (test ! -s '$pidfile' || ! kill -0 \$(cat '$pidfile') 2>/dev/null)"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

pull_simpleperf() {
  local label="$1" cell="$2"
  local data="$REMOTE_RESULT_ROOT/$label.data"
  local report="$REMOTE_RESULT_ROOT/$label.report"
  pull_binary "$data" "$cell/simpleperf.data"
  adb_su "'$SIMPLEPERF_REMOTE' report -i '$data' --sort symbol,dso -o '$report' \
    >/dev/null 2>/dev/null || true"
  pull_raw "$report" "$cell/simpleperf.report"
}

run_cell() {
  local arm="$1" workers="$2" protocol="$3" flows="$4" payload="$5" burst="$6" load="$7" repeat="$8" observe="$9"
  local mode="vpp-hev-tun-single" worker_count=1 echo=true
  local source_port_base="$UDP_SOURCE_PORT_BASE"
  [[ "$workers" == 2 ]] && mode="vpp-hev-tun-multi" && worker_count=2
  [[ "$protocol" == tcp ]] && source_port_base="$TCP_SOURCE_PORT_BASE"
  [[ "$arm" == ingress-only || "$arm" == memcpy-cal ]] && echo=false
  local label="${arm}-w${workers}-${protocol}-f${flows}-p${payload}-b${burst}-${load}-o${observe}-r${repeat}"
  local cell="$RESULT_DIR/$label"
  local simpleperf_expected=false
  (( payload >= 21 )) || { echo "payload must be >=21 for S125 payload format: $payload" >&2; return 1; }
  if [[ "$SIMPLEPERF" == 1 && "$arm" == full &&
        ("${SIMPLEPERF_FORCE:-0}" == 1 ||
         ("$flows" == 32 && "$payload" == 1400 && "$burst" == 32 &&
          "$load" == saturating)) ]]; then
    simpleperf_expected=true
  fi
  mkdir -p "$cell"
  (( CELL_COUNT += 1 ))
  if (( THERMAL_GUARD_EVERY > 0 && CELL_COUNT > 1 &&
        (CELL_COUNT - 1) % THERMAL_GUARD_EVERY == 0 )); then
    thermal_guard "$CELL_COUNT" || {
      echo "thermal guard failed before $label" >&2
      return 1
    }
  fi
  stop_vpn
  # Android may keep the previous VPN route alive briefly after service stop.
  # Without this settle window the next IPv4 socket can report NoRouteToHost
  # even though the new VPP/TUN stage is already registered.
  if (( CELL_COUNT > 1 )); then
    sleep "$VPN_RESTART_SETTLE_SECONDS"
  fi
  adb_su "rm -f '$REMOTE_APP_LOG' '$REMOTE_CLI_LOG' '$REMOTE_APP_FILES/vpp/vpp-stdout.log' '$REMOTE_APP_FILES/vpp/logs/vpp.log'"
  start_vpn "$mode" "$arm" "$observe"
  local vpp_pid
  vpp_pid="$(wait_vpp_ready)" || { echo "VPP did not become ready: $label" >&2; return 1; }
  wait_poc7_registered || {
    echo "POC-7 plugin did not register before traffic: $label" >&2
    echo "poc7_registration_missing=1" >"$cell/validity.raw"
    pull_raw "$REMOTE_CLI_LOG" "$cell/vpp-show.raw"
    pull_raw "$REMOTE_APP_FILES/vpp/logs/vpp.log" "$cell/vpp.log.raw"
    stop_vpn
    return 1
  }
  # Plugin registration proves VPP/TUN ownership, not that Android has
  # installed the new VPN route for the app's next TCP connect.  Give the
  # framework a deterministic settling window before starting the probe.
  sleep "$VPN_READY_SETTLE_SECONDS"
  collect_resource before "$vpp_pid" "$cell/resource-before.raw"
  printf '{\n  "schema":"s125-poc7/v2",\n  "runnerVersion":"%s",\n  "label":"%s",\n  "arm":"%s",\n  "workers":%d,\n  "protocol":"%s",\n  "flows":%d,\n  "sourcePortBase":%d,\n  "payloadBytes":%d,\n  "burst":%d,\n  "load":"%s",\n  "expectEcho":%s,\n  "observe":"%s",\n  "warmupSeconds":%d,\n  "steadySeconds":%d,\n  "drainSeconds":%d,\n  "reconnectEvery":%d,\n  "repeat":%d,\n  "device":"%s",\n  "deviceModel":"%s",\n  "deviceFingerprint":"%s",\n  "androidRelease":"%s",\n  "apkSha256":"%s",\n  "vppPluginSha256":"%s",\n  "hevLibrarySha256":"%s",\n  "gitRevision":"%s",\n  "simpleperfExpected":%s,\n  "udpClosedTimeoutMs":%d,\n  "udpSaturatingTimeoutMs":%d,\n  "fireAndCountPacingNsPerPacket":10000000,\n  "vppPid":"%s"\n}\n' "$RUNNER_VERSION" "$label" "$arm" "$worker_count" "$protocol" "$flows" "$source_port_base" "$payload" "$burst" "$load" "$echo" "$observe" "$WARMUP_SECONDS" "$STEADY_SECONDS" "$DRAIN_SECONDS" "$RECONNECT_EVERY" "$repeat" "$DEVICE_SERIAL" "$DEVICE_MODEL" "$DEVICE_FINGERPRINT" "$DEVICE_RELEASE" "$APK_SHA256" "$VPP_PLUGIN_SHA256" "$HEV_LIB_SHA256" "$RUNNER_GIT_REV" "$simpleperf_expected" "$UDP_CLOSED_TIMEOUT_MS" "$UDP_SATURATING_TIMEOUT_MS" "$vpp_pid" >"$cell/manifest.json"
  printf '%s\n' "$VPN_RESTART_SETTLE_SECONDS" >"$cell/vpn-restart-settle-seconds.raw"
  printf '%s\n' "$VPN_READY_SETTLE_SECONDS" >"$cell/vpn-ready-settle-seconds.raw"
  printf '%s\n' "$THERMAL_MAX_MILLIC" >"$cell/thermal-limit.millic"
  start_probe "$protocol" "$flows" "$payload" "$burst" "$load" "$echo"
  sleep "$WARMUP_SECONDS"
  collect_resource steady "$vpp_pid" "$cell/resource-steady.raw"
  if [[ "$simpleperf_expected" == true ]]; then
    start_simpleperf "$vpp_pid" "$label"
  fi
  if [[ -n "$PAIR_OBSERVE_SEQUENCE" ]]; then
    local pair_file="$cell/pair-observe.raw"
    : >"$pair_file"
    local pair_mode pair_start pair_end
    IFS=',' read -r -a pair_modes <<<"$PAIR_OBSERVE_SEQUENCE"
    for pair_mode in "${pair_modes[@]}"; do
      case "$pair_mode" in
        off|sample64|full) ;;
        *) echo "invalid paired observe mode: $pair_mode" >&2; return 1 ;;
      esac
      pair_start="$(date +%s%N)"
      printf '# pair mode=%s start_monotonic_ns=%s\n' "$pair_mode" "$pair_start" >>"$pair_file"
      run_vpp_cli "s124-vpn-tun observe $pair_mode" >>"$pair_file" 2>&1 || {
        echo "paired observe command failed: $pair_mode" >&2
        echo "paired-observe-command-failed=$pair_mode" >>"$cell/validity.raw"
        break
      }
      run_vpp_cli "$PAIR_OBSERVE_SHOW_COMMAND" >>"$pair_file" 2>&1 || true
      sleep "$PAIR_OBSERVE_INTERVAL_SECONDS"
      pair_end="$(date +%s%N)"
      printf '# pair mode=%s end_monotonic_ns=%s\n' "$pair_mode" "$pair_end" >>"$pair_file"
      run_vpp_cli "$PAIR_OBSERVE_SHOW_COMMAND" >>"$pair_file" 2>&1 || true
    done
  fi
  wait_probe_done || echo "probe_timeout=1" >"$cell/validity.raw"
  if [[ "$simpleperf_expected" == true ]]; then
    wait_simpleperf "$label" || echo "simpleperf_timeout=1" >>"$cell/validity.raw"
  fi
  collect_resource after "$vpp_pid" "$cell/resource-after.raw"
  pull_raw "$REMOTE_APP_LOG" "$cell/app.log"
  pull_raw "$REMOTE_CLI_LOG" "$cell/vpp-show.raw"
  pull_raw "$REMOTE_APP_FILES/vpp/vpp-stdout.log" "$cell/vpp-stdout.raw"
  pull_raw "$REMOTE_APP_FILES/vpp/logs/vpp.log" "$cell/vpp.log.raw"
  if [[ "$simpleperf_expected" == true ]]; then
    pull_simpleperf "$label" "$cell"
  fi
  stop_vpn
  if [[ -s "$cell/app.log" && -s "$cell/vpp-show.raw" ]]; then
    python3 "$SCRIPT_DIR/s125-parse-results.py" "$cell" \
      -o "$cell/cell-summary.json" || echo "parser_failed=1" >>"$cell/validity.raw"
  else
    echo "raw_missing=1" >"$cell/validity.raw"
  fi
  echo "cell=$label"
}

run_tcp_handshake_gate() {
  local saved_warmup="$WARMUP_SECONDS"
  local saved_steady="$STEADY_SECONDS"
  local saved_drain="$DRAIN_SECONDS"
  local gate_cell="$RESULT_DIR/full-w1-tcp-f1-p33-b1-closed-ofull-r0"
  WARMUP_SECONDS="$TCP_GATE_WARMUP_SECONDS"
  STEADY_SECONDS="$TCP_GATE_STEADY_SECONDS"
  DRAIN_SECONDS="$TCP_GATE_DRAIN_SECONDS"
  run_cell full 1 tcp 1 33 1 closed 0 full
  WARMUP_SECONDS="$saved_warmup"
  STEADY_SECONDS="$saved_steady"
  DRAIN_SECONDS="$saved_drain"
  [[ -s "$gate_cell/cell-summary.json" ]] || {
    TCP_HANDSHAKE_GATE_RESULT="missing-summary"
    echo "TCP handshake gate summary missing: $gate_cell" >&2
    return 1
  }
  if python3 - "$gate_cell/cell-summary.json" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
gate = summary.get("tcpHandshake", {})
required = (
    summary.get("valid") is True,
    gate.get("appReady") is True,
    gate.get("inputSynPackets", 0) > 0,
    gate.get("outputSynAckPackets", 0) > 0,
    gate.get("inputAckPackets", 0) > 0,
    gate.get("inputDataPackets", 0) > 0,
    gate.get("outputDataPackets", 0) > 0,
)
if not all(required):
    print("tcp-handshake-gate-failed", summary.get("reasons"), file=sys.stderr)
    raise SystemExit(1)
PY
  then
    TCP_HANDSHAKE_GATE_RESULT="passed"
  else
    TCP_HANDSHAKE_GATE_RESULT="failed"
    return 1
  fi
}

case "$TIER" in
  0) ARMS="${ARMS:-full udp-reflect ingress-only memcpy-cal}"; PROTOCOLS="${PROTOCOLS:-udp}"; FLOWS="${FLOWS:-1}"; PAYLOADS="${PAYLOADS:-33 1400}"; BURSTS="${BURSTS:-1 32}"; LOADS="${LOADS:-saturating}"; OBSERVES="${OBSERVES:-off sample64 full}"; RECONNECT_EVERY="${RECONNECT_EVERY:-0}" ;;
  1) ARMS="${ARMS:-full}"; PROTOCOLS="${PROTOCOLS:-udp tcp}"; FLOWS="${FLOWS:-1 8 32}"; PAYLOADS="${PAYLOADS:-33 512 1400}"; BURSTS="${BURSTS:-1 32}"; LOADS="${LOADS:-closed saturating}"; OBSERVES="${OBSERVES:-sample64}"; RECONNECT_EVERY="${RECONNECT_EVERY:-0}" ;;
  2) ARMS="${ARMS:-full}"; PROTOCOLS="${PROTOCOLS:-udp tcp}"; FLOWS="${FLOWS:-8 32}"; PAYLOADS="${PAYLOADS:-33 1400}"; BURSTS="${BURSTS:-1 32}"; LOADS="${LOADS:-saturating}"; OBSERVES="${OBSERVES:-full}"; RECONNECT_EVERY="${RECONNECT_EVERY:-5}" ;;
  *) echo "unknown TIER=$TIER" >&2; exit 2 ;;
esac
WORKERS="${WORKERS:-1 2}"

if [[ " $ARMS " == *" full "* && "${REQUIRE_POC7_TCP_METRIC:-1}" == 1 ]]; then
  if ! unzip -p "$APK" 'lib/arm64-v8a/libhev-socks5-tunnel.so' 2>/dev/null \
      | strings | grep 'flow_stack_owner_tcp_copy_metrics' >/dev/null; then
    echo "APK HEV library lacks POC-7 TCP copy metric; build with android-build-hev-poc7.sh" >&2
    exit 1
  fi
fi
if [[ " $ARMS " == *" udp-reflect "* ||
      " $ARMS " == *" ingress-only "* ||
      " $ARMS " == *" memcpy-cal "* ]]; then
  if ! unzip -Z1 "$APK" 2>/dev/null \
      | grep -qx 'lib/arm64-v8a/hev_external_driver_poc_plugin.so'; then
    echo "APK lacks hev_external_driver_poc_plugin.so; build with VPP_POC_PLUGIN" >&2
    exit 1
  fi
fi
if [[ "$TIER" == 2 && "${REQUIRE_SIMPLEPERF:-1}" == 1 && "$SIMPLEPERF" != 1 ]]; then
  echo "Tier 2 requires SIMPLEPERF=1 for the registered UDP/TCP representative cells" >&2
  exit 1
fi

if [[ -z "$VPP_PLUGIN_SHA256" ]] && unzip -Z1 "$APK" 2>/dev/null \
    | grep -qx 'lib/arm64-v8a/hev_external_driver_poc_plugin.so'; then
  VPP_PLUGIN_SHA256="$(sha256_apk_member 'lib/arm64-v8a/hev_external_driver_poc_plugin.so')"
fi
if [[ -z "$HEV_LIB_SHA256" ]] && unzip -Z1 "$APK" 2>/dev/null \
    | grep -qx 'lib/arm64-v8a/libhev-socks5-tunnel.so'; then
  HEV_LIB_SHA256="$(sha256_apk_member 'lib/arm64-v8a/libhev-socks5-tunnel.so')"
fi

trap stop_vpn EXIT
if [[ "$TCP_HANDSHAKE_GATE" == 1 ]]; then
  run_tcp_handshake_gate || {
    echo "TCP packet-path gate failed; formal POC-7 matrix is not started" >&2
    exit 1
  }
fi
for arm in $ARMS; do
  for workers in $WORKERS; do
    for protocol in $PROTOCOLS; do
      for flows in $FLOWS; do
        for payload in $PAYLOADS; do
          for burst in $BURSTS; do
            for load in $LOADS; do
              for repeat in $(seq 1 "$REPEATS"); do
                for observe in $OBSERVES; do
                  run_cell "$arm" "$workers" "$protocol" "$flows" "$payload" "$burst" "$load" "$repeat" "$observe"
                done
              done
            done
          done
        done
      done
    done
  done
done
if [[ "$TIER" == 0 && "$TCP_COPY_CALIBRATE" == 1 ]]; then
  for repeat in $(seq 1 "$REPEATS"); do
    for observe in off sample64 full; do
      run_cell full 1 tcp 1 33 1 saturating "$repeat" "$observe"
    done
  done
fi
printf '{\n  "schema":"s125-poc7-run/v2",\n  "runnerVersion":"%s",\n  "resultDir":"%s",\n  "device":"%s",\n  "deviceModel":"%s",\n  "deviceFingerprint":"%s",\n  "androidRelease":"%s",\n  "apkSha256":"%s",\n  "vppPluginSha256":"%s",\n  "hevLibrarySha256":"%s",\n  "gitRevision":"%s",\n  "tier":%d,\n  "repeats":%d,\n  "cellCount":%d,\n  "tcpHandshakeGate":"%s",\n  "udpSourcePortBase":%d,\n  "tcpSourcePortBase":%d,\n  "udpClosedTimeoutMs":%d,\n  "udpSaturatingTimeoutMs":%d\n}\n' "$RUNNER_VERSION" "$RESULT_DIR" "$DEVICE_SERIAL" "$DEVICE_MODEL" "$DEVICE_FINGERPRINT" "$DEVICE_RELEASE" "$APK_SHA256" "$VPP_PLUGIN_SHA256" "$HEV_LIB_SHA256" "$RUNNER_GIT_REV" "$TIER" "$REPEATS" "$CELL_COUNT" "$TCP_HANDSHAKE_GATE_RESULT" "$UDP_SOURCE_PORT_BASE" "$TCP_SOURCE_PORT_BASE" "$UDP_CLOSED_TIMEOUT_MS" "$UDP_SATURATING_TIMEOUT_MS" >"$RESULT_DIR/run-manifest.json"
mapfile -t RESULT_CELLS < <(find "$RESULT_DIR" -mindepth 1 -maxdepth 1 -type d -print | sort)
if (( ${#RESULT_CELLS[@]} > 0 )); then
  python3 "$SCRIPT_DIR/s125-parse-results.py" "${RESULT_CELLS[@]}" \
    -o "$RESULT_DIR/run-summary.json"
fi
printf 'results=%s\n' "$RESULT_DIR"
