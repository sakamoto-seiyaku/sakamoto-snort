#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-59 Android L4 release budget probe.
#
# This is a record-first budget collector for the current Android product path.
# It does not approve a release. It records debug or release-candidate Root/VPN
# measurements for workflow latency, nominal download throughput,
# drop/capacity/corrective-handoff counters, CPU/RSS, thermal status, shutdown
# drain timing, and script-enforced budget threshold pass/fail decisions.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s59-release-budget-probe}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
S59_APK_VARIANT="${S59_APK_VARIANT:-debug}"
case "$S59_APK_VARIANT" in
  debug)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
    S59_BUILD_SCRIPT="${S59_BUILD_SCRIPT:-app/android-runtime/scripts/build-debug-apk.sh}"
    ;;
  release-candidate)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-release-candidate.apk}"
    S59_BUILD_SCRIPT="${S59_BUILD_SCRIPT:-app/android-runtime/scripts/build-release-candidate-apk.sh}"
    ;;
  *)
    echo "unsupported S59_APK_VARIANT: $S59_APK_VARIANT" >&2
    exit 1
    ;;
esac
S59_BUILD_APK="${S59_BUILD_APK:-1}"
S59_INSTALL_APK="${S59_INSTALL_APK:-1}"
S59_PROFILE_LIST="${S59_PROFILE_LIST:-root vpn}"
S59_IDLE_SEC="${S59_IDLE_SEC:-2}"
S59_PROBE_COUNT="${S59_PROBE_COUNT:-3}"
S59_TRAFFIC_HOST="${S59_TRAFFIC_HOST:-1.1.1.1}"
S59_TRAFFIC_PORT="${S59_TRAFFIC_PORT:-80}"
S59_TRAFFIC_TIMEOUT_MILLIS="${S59_TRAFFIC_TIMEOUT_MILLIS:-1500}"
S59_DOWNLOAD_BYTES="${S59_DOWNLOAD_BYTES:-500000}"
S59_DOWNLOAD_TIMEOUT_SEC="${S59_DOWNLOAD_TIMEOUT_SEC:-20}"
S59_DOWNLOAD_URL="${S59_DOWNLOAD_URL:-https://speed.cloudflare.com/__down?bytes=${S59_DOWNLOAD_BYTES}}"
S59_THROUGHPUT_TXN_COUNT="${S59_THROUGHPUT_TXN_COUNT:-10}"
S59_SCREEN_OFF_SEC="${S59_SCREEN_OFF_SEC:-10}"
S59_BUDGET_MAX_WORKFLOW_P99_MS="${S59_BUDGET_MAX_WORKFLOW_P99_MS:-1500}"
S59_BUDGET_MIN_DOWNLOAD_MBPS="${S59_BUDGET_MIN_DOWNLOAD_MBPS:-1.00}"
S59_BUDGET_MIN_TXN_TPS="${S59_BUDGET_MIN_TXN_TPS:-1.00}"
S59_BUDGET_MAX_TXN_FAILURES="${S59_BUDGET_MAX_TXN_FAILURES:-1}"
S59_BUDGET_MAX_IDLE_CPU_PCT="${S59_BUDGET_MAX_IDLE_CPU_PCT:-10.00}"
S59_BUDGET_MAX_ACTIVE_CPU_PCT="${S59_BUDGET_MAX_ACTIVE_CPU_PCT:-25.00}"
S59_BUDGET_MAX_RSS_KB="${S59_BUDGET_MAX_RSS_KB:-65536}"
S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS="${S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS:-10000}"
S59_BUDGET_MAX_FLOW_CAPACITY_MISSES="${S59_BUDGET_MAX_FLOW_CAPACITY_MISSES:-0}"
S59_BUDGET_MAX_OWNER_FAULTS="${S59_BUDGET_MAX_OWNER_FAULTS:-0}"
S59_BUDGET_MAX_THERMAL_STATUS="${S59_BUDGET_MAX_THERMAL_STATUS:-2}"
S59_BUDGET_MIN_SCREEN_OFF_SEC="${S59_BUDGET_MIN_SCREEN_OFF_SEC:-10}"
export S59_BUDGET_MAX_WORKFLOW_P99_MS
export S59_BUDGET_MIN_DOWNLOAD_MBPS
export S59_BUDGET_MIN_TXN_TPS
export S59_BUDGET_MAX_TXN_FAILURES
export S59_BUDGET_MAX_IDLE_CPU_PCT
export S59_BUDGET_MAX_ACTIVE_CPU_PCT
export S59_BUDGET_MAX_RSS_KB
export S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS
export S59_BUDGET_MAX_FLOW_CAPACITY_MISSES
export S59_BUDGET_MAX_OWNER_FAULTS
export S59_BUDGET_MAX_THERMAL_STATUS
export S59_BUDGET_MIN_SCREEN_OFF_SEC
S59_FORWARD_PORT="${S59_FORWARD_PORT:-60659}"
S59_CLEANUP_ON_EXIT="${S59_CLEANUP_ON_EXIT:-1}"
STATE_PATH="files/runtime-state/snapshot.properties"
PROBE_RESULT_PATH="files/debug/traffic-probe.properties"
DOWNLOAD_RESULT_PATH="files/debug/download-probe.properties"

mkdir -p "$RESULT_DIR"
BUDGET_SUMMARY="${RESULT_DIR}/budget-summary.properties"
: >"$BUDGET_SUMMARY"
if [[ "${S59_BUDGET_LOGGING:-0}" != "1" ]]; then
  export S59_BUDGET_LOGGING=1
  exec > >(tee "${RESULT_DIR}/matrix.log") 2>&1
fi

kv() {
  local line="$1=$2"
  printf '%s\n' "$line"
  if [[ -n "${BUDGET_SUMMARY:-}" ]]; then
    printf '%s\n' "$line" >>"$BUDGET_SUMMARY"
  fi
}

section() {
  printf '\n## %s\n' "$1"
}

now_ms() {
  date +%s%3N
}

app_file_path() {
  printf '/data/user/0/%s/%s\n' "$PACKAGE" "$1"
}

app_file_cat() {
  local relative_path="$1"
  adb_cmd shell run-as "$PACKAGE" cat "$relative_path" 2>/dev/null \
    || adb_su "cat $(shell_single_quote "$(app_file_path "$relative_path")") 2>/dev/null" \
    || true
}

app_file_rm() {
  local relative_path="$1"
  adb_cmd shell run-as "$PACKAGE" rm -f "$relative_path" >/dev/null 2>&1 \
    || adb_su "rm -f $(shell_single_quote "$(app_file_path "$relative_path")")" \
      >/dev/null 2>&1 \
    || true
}

read_snapshot() {
  app_file_cat "$STATE_PATH" | tr -d '\r' || true
}

snapshot_value_from() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

wait_for_snapshot() {
  local out_file="$1"
  local attempts="${2:-45}"
  shift 2
  local state=""
  for _ in $(seq 1 "$attempts"); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"$out_file"
    local matched=1
    local pattern
    for pattern in "$@"; do
      if ! grep -Fxq "$pattern" <<<"$state"; then
        matched=0
        break
      fi
    done
    if [[ "$matched" == "1" ]]; then
      printf '%s\n' "$state"
      return 0
    fi
    sleep 1
  done
  return 1
}

start_profile() {
  local profile="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez runtimeStart true \
    --es runtimeProfile "$profile" >"${out_dir}/start.intent.log" 2>&1
  wait_for_snapshot "${out_dir}/snapshot.running" 60 \
    "state=running" "profile=$profile" "coreHealth=ok" \
    || {
      cat "${out_dir}/snapshot.running" >&2 || true
      return 1
    }
}

stop_profile() {
  local profile="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  local start_ms end_ms elapsed_ms stopped
  start_ms="$(now_ms)"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
    >"${out_dir}/stop.intent.log" 2>&1
  stopped="$(wait_for_snapshot "${out_dir}/snapshot.stopped" 45 \
    "state=stopped" "mayBeActive=false" "adapterReadiness=unavailable")" \
    || {
      cat "${out_dir}/snapshot.stopped" >&2 || true
      return 1
    }
  end_ms="$(now_ms)"
  elapsed_ms=$((end_ms - start_ms))
  kv "${profile}.shutdownDrain.ms" "$elapsed_ms"
  printf '%s\n' "$stopped" >"${out_dir}/snapshot.stopped"
}

pid_alive() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ && "$pid" != 0 ]] || return 1
  adb_su "kill -0 $pid" >/dev/null 2>&1
}

proc_ticks() {
  local pid="$1"
  adb_su "awk '{ print \$14 + \$15 }' /proc/$pid/stat 2>/dev/null" \
    | tr -d '\r\n'
}

proc_rss_kb() {
  local pid="$1"
  adb_su "awk '/^VmRSS:/ { print \$2 }' /proc/$pid/status 2>/dev/null" \
    | tr -d '\r\n'
}

clk_tck() {
  adb_cmd shell getconf CLK_TCK 2>/dev/null | tr -d '\r\n' || printf '100'
}

sample_idle_cpu() {
  local profile="$1"
  local pid="$2"
  local out_dir="$3"
  local ticks0 ticks1 rss0 rss1 tick_hz pct
  ticks0="$(proc_ticks "$pid")"
  rss0="$(proc_rss_kb "$pid")"
  sleep "$S59_IDLE_SEC"
  ticks1="$(proc_ticks "$pid")"
  rss1="$(proc_rss_kb "$pid")"
  tick_hz="$(clk_tck)"
  pct="$(python3 - "$ticks0" "$ticks1" "$tick_hz" "$S59_IDLE_SEC" <<'PY'
import sys
t0, t1, hz, sec = map(float, sys.argv[1:])
print(f"{max(0.0, (t1 - t0) * 100.0 / max(1.0, hz * sec)):.2f}")
PY
)"
  {
    kv "pid" "$pid"
    kv "ticks.before" "${ticks0:-0}"
    kv "ticks.after" "${ticks1:-0}"
    kv "rssKb.before" "${rss0:-0}"
    kv "rssKb.after" "${rss1:-0}"
    kv "cpuPct" "$pct"
  } >"${out_dir}/cpu-rss-idle.properties"
  kv "${profile}.idle.cpuPct" "$pct"
  kv "${profile}.idle.rssKb" "${rss1:-0}"
}

thermal_status() {
  adb_cmd shell dumpsys thermalservice 2>/dev/null | tr -d '\r' \
    | awk -F: '/Thermal Status:/ { gsub(/^ +| +$/, "", $2); print $2; found=1; exit } END { if (!found) print "unknown" }'
}

collect_thermal() {
  local label="$1"
  local out_file="$2"
  adb_cmd shell dumpsys thermalservice >"$out_file" 2>&1 || true
  kv "$label" "$(thermal_status)"
}

battery_node() {
  local node="$1"
  local value
  value="$(adb_cmd shell cat "/sys/class/power_supply/battery/${node}" 2>/dev/null \
    | tr -d '\r\n' || true)"
  if [[ -z "$value" ]]; then
    value="unavailable"
  fi
  printf '%s\n' "$value"
}

power_file_value() {
  local file="$1"
  local pattern="$2"
  awk -F= -v pattern="$pattern" '
    index($1, pattern) > 0 {
      gsub(/\r/, "", $2)
      gsub(/^ +| +$/, "", $2)
      print $2
      found=1
      exit
    }
    END { if (!found) print "unknown" }
  ' "$file"
}

collect_power_snapshot() {
  local label="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  adb_cmd shell dumpsys power >"${out_dir}/power.txt" 2>&1 || true
  adb_cmd shell dumpsys deviceidle >"${out_dir}/deviceidle.txt" 2>&1 || true
  adb_cmd shell dumpsys battery >"${out_dir}/battery.txt" 2>&1 || true
  {
    kv "currentNowUa" "$(battery_node current_now)"
    kv "voltageNowUv" "$(battery_node voltage_now)"
    kv "capacityPct" "$(battery_node capacity)"
    kv "temperatureTenthsC" "$(battery_node temp)"
    kv "wakefulness" "$(power_file_value "${out_dir}/power.txt" "mWakefulness")"
    kv "interactive" "$(power_file_value "${out_dir}/power.txt" "mInteractive")"
  } >"${out_dir}/power-proxy.properties"
  while IFS= read -r line; do
    kv "${label}.${line%%=*}" "${line#*=}"
  done <"${out_dir}/power-proxy.properties"
}

measure_screen_off_power_proxy() {
  local profile="$1"
  local out_dir="$2"
  local screen_dir="${out_dir}/screen-off-power"
  mkdir -p "$screen_dir"
  collect_power_snapshot "${profile}.screenOff.before" "${screen_dir}/before"
  adb_cmd shell input keyevent 223 >"${screen_dir}/screen-off.intent.log" 2>&1 || true
  sleep 2
  collect_power_snapshot "${profile}.screenOff.start" "${screen_dir}/start"
  sleep "$S59_SCREEN_OFF_SEC"
  collect_power_snapshot "${profile}.screenOff.end" "${screen_dir}/end"
  adb_cmd shell input keyevent 224 >"${screen_dir}/screen-on.intent.log" 2>&1 || true
  sleep 1
  collect_power_snapshot "${profile}.screenOff.after" "${screen_dir}/after"
  kv "${profile}.screenOffPower.result" "RECORDED_PROXY"
  kv "${profile}.screenOffPower.durationSec" "$S59_SCREEN_OFF_SEC"
  kv "${profile}.screenOffPower.proxy" "power_supply_current_now_dumpsys_power_deviceidle"
}

query_control_json() {
  local name="$1"
  local command="$2"
  local args="${3:-{}}"
  python3 - "$S59_FORWARD_PORT" "$RESULT_DIR" "$name" "$command" "$args" <<'PY'
import json
import pathlib
import socket
import sys

port = int(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])
name = sys.argv[3]
command = sys.argv[4]
raw_args = sys.argv[5].strip() if len(sys.argv) > 5 else "{}"
(result_dir / f"{name}.args.raw").write_text(raw_args + "\n")
args, _ = json.JSONDecoder().raw_decode(raw_args or "{}")
(result_dir / f"{name}.args.json").write_text(json.dumps(args, sort_keys=True) + "\n")
payload = json.dumps({"id": 1, "cmd": command, "args": args},
                     separators=(",", ":")).encode()
frame = str(len(payload)).encode() + b":" + payload + b","
with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
    sock.sendall(frame)
    digits = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise RuntimeError("eof before netstring length")
        if byte == b":":
            break
        digits += byte
    length = int(digits)
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise RuntimeError("eof in netstring body")
        body += chunk
    if sock.recv(1) != b",":
        raise RuntimeError("missing netstring terminator")
response = json.loads(body.decode())
(result_dir / f"{name}.json").write_text(
    json.dumps(response, indent=2, sort_keys=True) + "\n")
if not response.get("ok"):
    raise SystemExit(1)
print(json.dumps(response, sort_keys=True))
PY
}

summarize_adapter_status() {
  local profile="$1"
  local json_file="$2"
  python3 - "$profile" "$json_file" <<'PY'
import json
import sys

profile = sys.argv[1]
data = json.load(open(sys.argv[2]))
result = data.get("result", {})
drop = result.get("policyDropActivity", {})
allow = result.get("allowedFlowActivity", {})

def emit(k, v):
    print(f"{profile}.{k}={v}")

for key in [
    "packetsSeen", "droppedPackets", "acceptedPackets", "forwardedPackets",
    "capacityPassThroughPackets", "capacityPolicyBypassPackets",
    "ownerFaultPassThroughPackets", "ownerFaultRuntimeDrops",
    "ownerGuardMismatches", "transportFailedPackets",
    "queueCapacity", "queueHighWatermark", "queueCompletionCapacity",
    "queueCompletionHighWatermark",
    "flowTableEntries", "flowTableCapacity", "flowTableHighWatermark",
    "flowTableCapacityMisses",
]:
    if key in result:
        emit(f"adapter.{key}", result.get(key, 0))
emit("activity.drop.records", drop.get("records", 0))
emit("activity.drop.capacity", drop.get("capacity", 0))
emit("activity.drop.evicted", drop.get("evictedRecords", 0))
emit("activity.allowed.records", allow.get("records", 0))
emit("activity.allowed.capacity", allow.get("capacity", 0))
emit("activity.allowed.evicted", allow.get("evictedRecords", 0))
PY
}

read_probe_result() {
  app_file_cat "$PROBE_RESULT_PATH" | tr -d '\r' || true
}

read_download_result() {
  app_file_cat "$DOWNLOAD_RESULT_PATH" | tr -d '\r' || true
}

run_workflow_latency_probes() {
  local profile="$1"
  local out_dir="$2"
  local lat_file="${out_dir}/workflow-latency-ms.txt"
  local result_file="${out_dir}/workflow-probe-results.properties"
  : >"$lat_file"
  : >"$result_file"
  local i start_ms end_ms elapsed result
  for i in $(seq 1 "$S59_PROBE_COUNT"); do
    app_file_rm "$PROBE_RESULT_PATH"
    start_ms="$(now_ms)"
    adb_cmd shell am start -n "$ACTIVITY" \
      --ez debugTraffic true \
      --es debugTrafficHost "$S59_TRAFFIC_HOST" \
      --ei debugTrafficPort "$S59_TRAFFIC_PORT" \
      --ei debugTrafficTimeoutMillis "$S59_TRAFFIC_TIMEOUT_MILLIS" \
      >"${out_dir}/workflow-probe-${i}.intent.log" 2>&1
    result=""
    for _ in $(seq 1 20); do
      result="$(read_probe_result)"
      if grep -q '^result=' <<<"$result"; then
        break
      fi
      sleep 0.2
    done
    end_ms="$(now_ms)"
    elapsed=$((end_ms - start_ms))
    printf '%s\n' "$elapsed" >>"$lat_file"
    {
      printf 'probe.%s.elapsedMs=%s\n' "$i" "$elapsed"
      printf '%s\n' "$result" | sed "s/^/probe.${i}./"
    } >>"$result_file"
  done
  python3 - "$profile" "$lat_file" <<'PY'
import math
import sys

profile = sys.argv[1]
values = sorted(int(x.strip()) for x in open(sys.argv[2]) if x.strip())
def pct(p):
    if not values:
        return 0
    idx = math.ceil((p / 100.0) * len(values)) - 1
    idx = min(max(idx, 0), len(values) - 1)
    return values[idx]
print(f"{profile}.workflowLatency.samples={len(values)}")
print(f"{profile}.workflowLatency.p50Ms={pct(50)}")
print(f"{profile}.workflowLatency.p95Ms={pct(95)}")
print(f"{profile}.workflowLatency.p99Ms={pct(99)}")
PY
}

run_tcp_transaction_rate() {
  local profile="$1"
  local out_dir="$2"
  local result_file="${out_dir}/throughput-txn-probe-results.properties"
  local i start_ms end_ms elapsed_ms result code successes=0 failures=0
  : >"$result_file"
  start_ms="$(now_ms)"
  for i in $(seq 1 "$S59_THROUGHPUT_TXN_COUNT"); do
    app_file_rm "$PROBE_RESULT_PATH"
    adb_cmd shell am start -n "$ACTIVITY" \
      --ez debugTraffic true \
      --es debugTrafficHost "$S59_TRAFFIC_HOST" \
      --ei debugTrafficPort "$S59_TRAFFIC_PORT" \
      --ei debugTrafficTimeoutMillis "$S59_TRAFFIC_TIMEOUT_MILLIS" \
      >"${out_dir}/throughput-txn-${i}.intent.log" 2>&1
    result=""
    for _ in $(seq 1 20); do
      result="$(read_probe_result)"
      if grep -q '^result=' <<<"$result"; then
        break
      fi
      sleep 0.2
    done
    code="$(printf '%s\n' "$result" | snapshot_value_from result || true)"
    if [[ "$code" == "tcp_connect_succeeded" ]]; then
      successes=$((successes + 1))
    else
      failures=$((failures + 1))
    fi
    {
      printf 'probe.%s.result=%s\n' "$i" "${code:-missing}"
      printf '%s\n' "$result" | sed "s/^/probe.${i}./"
    } >>"$result_file"
  done
  end_ms="$(now_ms)"
  elapsed_ms=$((end_ms - start_ms))
  if [[ "$elapsed_ms" -le 0 ]]; then
    elapsed_ms=1
  fi
  python3 - "$successes" "$failures" "$elapsed_ms" <<'PY'
import sys
successes, failures, elapsed_ms = map(int, sys.argv[1:])
tps = successes / max(0.001, elapsed_ms / 1000.0)
print("result=txn_rate_recorded")
print(f"attempts={successes + failures}")
print(f"successes={successes}")
print(f"failures={failures}")
print(f"elapsedMs={elapsed_ms}")
print(f"tps={tps:.2f}")
PY
}

run_nominal_throughput() {
  local profile="$1"
  local pid="$2"
  local out_dir="$3"
  local start_ms end_ms elapsed_ms ticks0 ticks1 rss result txn_result
  ticks0="$(proc_ticks "$pid")"
  start_ms="$(now_ms)"
  app_file_rm "$DOWNLOAD_RESULT_PATH"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugDownload true \
    --es debugDownloadUrl "$S59_DOWNLOAD_URL" \
    --ei debugDownloadTimeoutMillis "$((S59_DOWNLOAD_TIMEOUT_SEC * 1000))" \
    --ei debugDownloadMaxBytes "$S59_DOWNLOAD_BYTES" \
    >"${out_dir}/download-probe.intent.log" 2>&1
  result=""
  for _ in $(seq 1 "$((S59_DOWNLOAD_TIMEOUT_SEC * 5 + 10))"); do
    result="$(read_download_result)"
    if grep -q '^result=' <<<"$result"; then
      break
    fi
    sleep 0.2
  done
  txn_result=""
  if ! grep -q '^result=download_succeeded$' <<<"$result"; then
    txn_result="$(run_tcp_transaction_rate "$profile" "$out_dir")"
    printf '%s\n' "$txn_result" >"${out_dir}/throughput-txn.properties"
  fi
  end_ms="$(now_ms)"
  ticks1="$(proc_ticks "$pid")"
  elapsed_ms=$((end_ms - start_ms))
  if [[ "$elapsed_ms" -le 0 ]]; then
    elapsed_ms=1
  fi
  rss="$(proc_rss_kb "$pid")"
  printf '%s\n' "$result" >"${out_dir}/download-probe.properties"
  python3 - "$profile" "$elapsed_ms" "$ticks0" "$ticks1" "$(clk_tck)" "$result" "$txn_result" <<'PY'
import sys
profile, ms, t0, t1, hz, raw, raw_txn = sys.argv[1:]
ms = max(1, int(ms))
t0 = float(t0 or 0)
t1 = float(t1 or 0)
hz = float(hz or 100)
props = {}
for line in raw.splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value
txn = {}
for line in raw_txn.splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        txn[key] = value
cpu_pct = max(0.0, (t1 - t0) * 100.0 / max(1.0, hz * (ms / 1000.0)))
result = props.get("result", "")
if result == "download_succeeded":
    print(f"{profile}.throughput.result=RECORDED_APP_DOWNLOAD")
    print(f"{profile}.throughput.bytes={props.get('bytes', '0')}")
    print(f"{profile}.throughput.elapsedMs={props.get('elapsedMs', str(ms))}")
    print(f"{profile}.throughput.mbps={props.get('mbps', '0.00')}")
elif txn.get("result") == "txn_rate_recorded":
    print(f"{profile}.throughput.result=RECORDED_APP_TCP_CONNECT_TXN_RATE")
    print(f"{profile}.throughput.txnAttempts={txn.get('attempts', '0')}")
    print(f"{profile}.throughput.txnSuccesses={txn.get('successes', '0')}")
    print(f"{profile}.throughput.txnFailures={txn.get('failures', '0')}")
    print(f"{profile}.throughput.elapsedMs={txn.get('elapsedMs', str(ms))}")
    print(f"{profile}.throughput.tps={txn.get('tps', '0.00')}")
    print(f"{profile}.throughput.downloadFallback={props.get('message', 'download_failed')}")
else:
    print(f"{profile}.throughput.result=UNAVAILABLE_APP_DOWNLOAD_FAILED")
    print(f"{profile}.throughput.bytes={props.get('bytes', '0')}")
    print(f"{profile}.throughput.elapsedMs={props.get('elapsedMs', str(ms))}")
    print(f"{profile}.throughput.message={props.get('message', 'missing_download_result')}")
print(f"{profile}.active.cpuPct={cpu_pct:.2f}")
PY
  kv "${profile}.active.rssKb" "${rss:-0}"
}

evaluate_budget_thresholds() {
  # Emits budget.result=PASS or budget.result=FAIL for the matrix gate.
  python3 - "$BUDGET_SUMMARY" "$S59_PROFILE_LIST" <<'PY'
import os
import sys

summary_path = sys.argv[1]
profiles = sys.argv[2].split()

props = {}
with open(summary_path, encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        props[key] = value

def env_float(name, default):
    return float(os.environ.get(name, default))

def env_int(name, default):
    return int(os.environ.get(name, default))

thresholds = {
    "workflow_p99_ms": env_float("S59_BUDGET_MAX_WORKFLOW_P99_MS", "1500"),
    "download_mbps": env_float("S59_BUDGET_MIN_DOWNLOAD_MBPS", "1.00"),
    "txn_tps": env_float("S59_BUDGET_MIN_TXN_TPS", "1.00"),
    "txn_failures": env_int("S59_BUDGET_MAX_TXN_FAILURES", "0"),
    "idle_cpu_pct": env_float("S59_BUDGET_MAX_IDLE_CPU_PCT", "10.00"),
    "active_cpu_pct": env_float("S59_BUDGET_MAX_ACTIVE_CPU_PCT", "25.00"),
    "rss_kb": env_float("S59_BUDGET_MAX_RSS_KB", "65536"),
    "shutdown_drain_ms": env_float("S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS", "10000"),
    "flow_capacity_misses": env_float("S59_BUDGET_MAX_FLOW_CAPACITY_MISSES", "0"),
    "owner_faults": env_float("S59_BUDGET_MAX_OWNER_FAULTS", "0"),
    "thermal_status": env_float("S59_BUDGET_MAX_THERMAL_STATUS", "2"),
    "screen_off_sec": env_float("S59_BUDGET_MIN_SCREEN_OFF_SEC", "10"),
}

def get(profile, suffix, default=""):
    return props.get(f"{profile}.{suffix}", default)

def as_float(value, default=0.0):
    try:
        return float(str(value).strip())
    except ValueError:
        return default

def as_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except ValueError:
        return default

def emit(key, value):
    print(f"{key}={value}")

failures = []

for profile in profiles:
    p99 = as_float(get(profile, "workflowLatency.p99Ms", "0"))
    workflow_ok = p99 > 0 and p99 <= thresholds["workflow_p99_ms"]
    emit(f"{profile}.budget.workflowLatency.maxP99Ms", int(thresholds["workflow_p99_ms"]))
    emit(f"{profile}.budget.workflowLatency.result", "PASS" if workflow_ok else "FAIL")
    if not workflow_ok:
        failures.append(f"{profile}.workflowLatency")

    throughput_result = get(profile, "throughput.result")
    throughput_ok = False
    throughput_basis = "unavailable"
    if throughput_result == "RECORDED_APP_DOWNLOAD":
        mbps = as_float(get(profile, "throughput.mbps", "0"))
        throughput_ok = mbps >= thresholds["download_mbps"]
        throughput_basis = f"download_mbps>={thresholds['download_mbps']:.2f}"
    elif throughput_result == "RECORDED_APP_TCP_CONNECT_TXN_RATE":
        tps = as_float(get(profile, "throughput.tps", "0"))
        failures_count = as_int(get(profile, "throughput.txnFailures", "999"))
        throughput_ok = (
            tps >= thresholds["txn_tps"]
            and failures_count <= thresholds["txn_failures"]
        )
        throughput_basis = (
            f"txn_tps>={thresholds['txn_tps']:.2f},"
            f"txn_failures<={thresholds['txn_failures']}"
        )
    emit(f"{profile}.budget.throughput.basis", throughput_basis)
    emit(f"{profile}.budget.throughput.result", "PASS" if throughput_ok else "FAIL")
    if not throughput_ok:
        failures.append(f"{profile}.throughput")

    idle_cpu = as_float(get(profile, "idle.cpuPct", "999"))
    active_cpu = as_float(get(profile, "active.cpuPct", "999"))
    idle_rss = as_float(get(profile, "idle.rssKb", "999999"))
    active_rss = as_float(get(profile, "active.rssKb", "999999"))
    cpu_rss_ok = (
        idle_cpu <= thresholds["idle_cpu_pct"]
        and active_cpu <= thresholds["active_cpu_pct"]
        and idle_rss <= thresholds["rss_kb"]
        and active_rss <= thresholds["rss_kb"]
    )
    emit(f"{profile}.budget.cpuRss.result", "PASS" if cpu_rss_ok else "FAIL")
    if not cpu_rss_ok:
        failures.append(f"{profile}.cpuRss")

    flow_misses = as_float(get(profile, "adapter.flowTableCapacityMisses", "0"))
    queue_capacity = as_float(get(profile, "adapter.queueCapacity", "0"))
    queue_hwm = as_float(get(profile, "adapter.queueHighWatermark", "0"))
    queue_ok = queue_capacity <= 0 or queue_hwm <= queue_capacity
    capacity_ok = (
        flow_misses <= thresholds["flow_capacity_misses"]
        and queue_ok
    )
    emit(f"{profile}.budget.capacity.result", "PASS" if capacity_ok else "FAIL")
    if not capacity_ok:
        failures.append(f"{profile}.capacity")

    owner_faults = (
        as_float(get(profile, "adapter.ownerFaultPassThroughPackets", "0"))
        + as_float(get(profile, "adapter.ownerFaultRuntimeDrops", "0"))
        + as_float(get(profile, "adapter.ownerGuardMismatches", "0"))
        + as_float(get(profile, "adapter.transportFailedPackets", "0"))
    )
    corrective_ok = owner_faults <= thresholds["owner_faults"]
    emit(f"{profile}.budget.correctiveHandoff.result", "PASS" if corrective_ok else "FAIL")
    if not corrective_ok:
        failures.append(f"{profile}.correctiveHandoff")

    power_ok = (
        get(profile, "screenOffPower.result") == "RECORDED_PROXY"
        and as_float(get(profile, "screenOffPower.durationSec", "0"))
        >= thresholds["screen_off_sec"]
    )
    emit(f"{profile}.budget.screenOffPowerProxy.result", "PASS" if power_ok else "FAIL")
    if not power_ok:
        failures.append(f"{profile}.screenOffPowerProxy")

    thermal_before = get(profile, "thermal.before", "unknown")
    thermal_after = get(profile, "thermal.after", "unknown")
    thermal_ok = (
        thermal_before != "unknown"
        and thermal_after != "unknown"
        and as_float(thermal_before, 999) <= thresholds["thermal_status"]
        and as_float(thermal_after, 999) <= thresholds["thermal_status"]
    )
    emit(f"{profile}.budget.thermal.result", "PASS" if thermal_ok else "FAIL")
    if not thermal_ok:
        failures.append(f"{profile}.thermal")

    drain_ms = as_float(get(profile, "shutdownDrain.ms", "999999"))
    drain_ok = drain_ms <= thresholds["shutdown_drain_ms"]
    emit(f"{profile}.budget.shutdownDrain.result", "PASS" if drain_ok else "FAIL")
    if not drain_ok:
        failures.append(f"{profile}.shutdownDrain")

if failures:
    emit("budget.failures", ",".join(failures))
    emit("budget.result", "FAIL")
else:
    emit("budget.failures", "none")
    emit("budget.result", "PASS")
PY
}

cleanup() {
  if [[ "$S59_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  adb_cmd shell input keyevent 224 >/dev/null 2>&1 || true
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
  adb_cmd forward --remove "tcp:${S59_FORWARD_PORT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

profile_status_command() {
  local profile="$1"
  if [[ "$profile" == "vpn" ]]; then
    printf '%s\n' "VPN_TUN.STATUS"
  else
    printf '%s\n' "NFQUEUE.STATUS"
  fi
}

measure_profile() {
  local profile="$1"
  local out_dir="${RESULT_DIR}/${profile}"
  local state pid status_cmd
  mkdir -p "$out_dir"
  section "profile_${profile}"
  state="$(start_profile "$profile" "$out_dir")"
  printf '%s\n' "$state" >"${out_dir}/snapshot.running"
  pid="$(printf '%s\n' "$state" | snapshot_value_from pid)"
  kv "${profile}.start.result" "PASS"
  kv "${profile}.pid" "$pid"
  kv "${profile}.version" "$(printf '%s\n' "$state" | snapshot_value_from version || true)"
  kv "${profile}.artifact" "$(printf '%s\n' "$state" | snapshot_value_from artifact || true)"
  kv "${profile}.abi" "$(printf '%s\n' "$state" | snapshot_value_from abi || true)"

  collect_thermal "${profile}.thermal.before" "${out_dir}/thermal.before.txt"
  sample_idle_cpu "$profile" "$pid" "$out_dir"

  setup_control_vnext_forward "$S59_FORWARD_PORT"
  status_cmd="$(profile_status_command "$profile")"
  query_control_json "${profile}/status.before" "$status_cmd" "{}" >/dev/null

  run_workflow_latency_probes "$profile" "$out_dir" | tee "${out_dir}/workflow-latency.properties"
  cat "${out_dir}/workflow-latency.properties" >>"$BUDGET_SUMMARY"
  run_nominal_throughput "$profile" "$pid" "$out_dir" | tee "${out_dir}/throughput.properties"
  cat "${out_dir}/throughput.properties" >>"$BUDGET_SUMMARY"

  query_control_json "${profile}/status.after" "$status_cmd" "{}" >/dev/null
  summarize_adapter_status "$profile" "${out_dir}/status.after.json" | tee "${out_dir}/adapter-summary.properties"
  cat "${out_dir}/adapter-summary.properties" >>"$BUDGET_SUMMARY"
  measure_screen_off_power_proxy "$profile" "$out_dir"
  collect_thermal "${profile}.thermal.after" "${out_dir}/thermal.after.txt"
  stop_profile "$profile" "$out_dir"
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-59-release-budget-probe"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "apkVariant" "$S59_APK_VARIANT"
if [[ "$S59_APK_VARIANT" == "release-candidate" ]]; then
  kv "releaseStatus" "release_candidate_non_debug_not_final_signing"
else
  kv "releaseStatus" "debug_apk_budget_probe_only"
fi
kv "workflowLatency" "p50/p95/p99_ms"
kv "nominalThroughput" "app_debug_download_mbps"
kv "cpuRss" "idle_and_download_active_proc_ticks_rss"
kv "screenOffPower" "short_screen_off_power_supply_current_now_proxy"
kv "thermal" "dumpsys_thermalservice_before_after"
kv "shutdownDrain" "runtimeStop_to_stopped_snapshot_ms"
kv "capacityHighWatermark" "adapter_queue_flow_table_and_activity_capacity_evictions"
kv "correctiveHandoff" "owner_fault_or_owner_guard_counters"

section "budget_thresholds"
kv "budget.threshold.workflowP99MaxMs" "$S59_BUDGET_MAX_WORKFLOW_P99_MS"
kv "budget.threshold.downloadMinMbps" "$S59_BUDGET_MIN_DOWNLOAD_MBPS"
kv "budget.threshold.txnMinTps" "$S59_BUDGET_MIN_TXN_TPS"
kv "budget.threshold.txnMaxFailures" "$S59_BUDGET_MAX_TXN_FAILURES"
kv "budget.threshold.idleCpuMaxPct" "$S59_BUDGET_MAX_IDLE_CPU_PCT"
kv "budget.threshold.activeCpuMaxPct" "$S59_BUDGET_MAX_ACTIVE_CPU_PCT"
kv "budget.threshold.rssMaxKb" "$S59_BUDGET_MAX_RSS_KB"
kv "budget.threshold.shutdownDrainMaxMs" "$S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS"
kv "budget.threshold.flowCapacityMissesMax" "$S59_BUDGET_MAX_FLOW_CAPACITY_MISSES"
kv "budget.threshold.ownerFaultsMax" "$S59_BUDGET_MAX_OWNER_FAULTS"
kv "budget.threshold.thermalStatusMax" "$S59_BUDGET_MAX_THERMAL_STATUS"
kv "budget.threshold.screenOffMinSec" "$S59_BUDGET_MIN_SCREEN_OFF_SEC"

section "device"
kv "device.model" "$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
kv "device.android" "$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
kv "device.sdk" "$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
kv "device.abi" "$(adb_cmd shell getprop ro.product.cpu.abi | tr -d '\r')"

section "build_install"
if [[ "$S59_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash $S59_BUILD_SCRIPT"
  (cd "$repo_root" && bash "$S59_BUILD_SCRIPT") \
    >"${RESULT_DIR}/build-apk.log" 2>&1
  kv "build.result" "PASS"
fi
[[ -f "$APK" ]] || {
  echo "missing APK: $APK" >&2
  exit 1
}
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$(sha256sum "$APK" | awk '{print $1}')"
if [[ "$S59_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi

adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
for profile in $S59_PROFILE_LIST; do
  measure_profile "$profile"
done

section "budget_result"
budget_eval="$(evaluate_budget_thresholds)"
printf '%s\n' "$budget_eval"
printf '%s\n' "$budget_eval" >>"$BUDGET_SUMMARY"
if grep -Fxq "budget.result=FAIL" <<<"$budget_eval"; then
  exit 1
fi

section "matrix_result"
kv "matrix.result" "PASS"
if [[ "$S59_APK_VARIANT" == "release-candidate" ]]; then
  kv "matrix.s59ReleaseBudgetProbe" "claimed_release_candidate_non_debug_not_final_signing"
else
  kv "matrix.s59ReleaseBudgetProbe" "claimed_debug_only"
fi
