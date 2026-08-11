#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-59 Android L4 release budget probe.
#
# This is a record-first budget collector for the current Android product path.
# It does not approve a release. It records debug-APK Root/VPN measurements for
# workflow latency, nominal download throughput, drop/capacity/corrective-handoff
# counters, CPU/RSS, thermal status, and shutdown drain timing.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s59-release-budget-probe}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
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
S59_FORWARD_PORT="${S59_FORWARD_PORT:-60659}"
S59_CLEANUP_ON_EXIT="${S59_CLEANUP_ON_EXIT:-1}"
STATE_PATH="files/runtime-state/snapshot.properties"
PROBE_RESULT_PATH="files/debug/traffic-probe.properties"
DOWNLOAD_RESULT_PATH="files/debug/download-probe.properties"

mkdir -p "$RESULT_DIR"
if [[ "${S59_BUDGET_LOGGING:-0}" != "1" ]]; then
  export S59_BUDGET_LOGGING=1
  exec > >(tee "${RESULT_DIR}/matrix.log") 2>&1
fi

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

now_ms() {
  date +%s%3N
}

read_snapshot() {
  adb_cmd shell run-as "$PACKAGE" cat "$STATE_PATH" 2>/dev/null | tr -d '\r' || true
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
  adb_cmd shell run-as "$PACKAGE" cat "$PROBE_RESULT_PATH" 2>/dev/null | tr -d '\r' || true
}

read_download_result() {
  adb_cmd shell run-as "$PACKAGE" cat "$DOWNLOAD_RESULT_PATH" 2>/dev/null | tr -d '\r' || true
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
    adb_cmd shell run-as "$PACKAGE" rm -f "$PROBE_RESULT_PATH" >/dev/null 2>&1 || true
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
    adb_cmd shell run-as "$PACKAGE" rm -f "$PROBE_RESULT_PATH" >/dev/null 2>&1 || true
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
  adb_cmd shell run-as "$PACKAGE" rm -f "$DOWNLOAD_RESULT_PATH" >/dev/null 2>&1 || true
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

cleanup() {
  if [[ "$S59_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
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
  run_nominal_throughput "$profile" "$pid" "$out_dir" | tee "${out_dir}/throughput.properties"

  query_control_json "${profile}/status.after" "$status_cmd" "{}" >/dev/null
  summarize_adapter_status "$profile" "${out_dir}/status.after.json" | tee "${out_dir}/adapter-summary.properties"
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
kv "releaseStatus" "debug_apk_budget_probe_only"
kv "workflowLatency" "p50/p95/p99_ms"
kv "nominalThroughput" "app_debug_download_mbps"
kv "cpuRss" "idle_and_download_active_proc_ticks_rss"
kv "thermal" "dumpsys_thermalservice_before_after"
kv "shutdownDrain" "runtimeStop_to_stopped_snapshot_ms"
kv "capacityHighWatermark" "adapter_flow_table_and_activity_capacity_evictions"
kv "correctiveHandoff" "owner_fault_or_owner_guard_counters"

section "device"
kv "device.model" "$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
kv "device.android" "$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
kv "device.sdk" "$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
kv "device.abi" "$(adb_cmd shell getprop ro.product.cpu.abi | tr -d '\r')"

section "build_install"
if [[ "$S59_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash app/android-runtime/scripts/build-debug-apk.sh"
  (cd "$repo_root" && bash app/android-runtime/scripts/build-debug-apk.sh) \
    >"${RESULT_DIR}/build-debug-apk.log" 2>&1
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

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s59ReleaseBudgetProbe" "claimed_debug_only"
