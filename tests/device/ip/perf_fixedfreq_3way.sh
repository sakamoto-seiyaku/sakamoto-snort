#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"
RUNNER="$IPMOD_DIR/run.sh"

source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

DURATION_S="${DURATION_S:-90}"
COOLDOWN_S="${COOLDOWN_S:-60}"
SETTLE_S="${SETTLE_S:-10}"
ORDER_CSV="${ORDER_CSV:-iprules_off_empty,iprules_on_empty,iprules_on_heavy}"
POLICY0_FREQ="${POLICY0_FREQ:-1328000}"
POLICY4_FREQ="${POLICY4_FREQ:-1328000}"
POLICY6_FREQ="${POLICY6_FREQ:-1426000}"
OUTPUT_DIR=""

IPTEST_PERF_LOAD_MODE="${IPTEST_PERF_LOAD_MODE:-mix}"
IPTEST_PERF_MIX_WORKERS="${IPTEST_PERF_MIX_WORKERS:-16}"
IPTEST_PERF_MIX_CONN_BYTES="${IPTEST_PERF_MIX_CONN_BYTES:-4096}"
IPTEST_PERF_MIX_HOST_COUNT="${IPTEST_PERF_MIX_HOST_COUNT:-4}"
IPTEST_PERF_MIX_PEER_COUNT="${IPTEST_PERF_MIX_PEER_COUNT:-16}"
IPTEST_PERF_MIX_PORT_COUNT="${IPTEST_PERF_MIX_PORT_COUNT:-8}"
HEAVY_TRAFFIC_RULES="${HEAVY_TRAFFIC_RULES:-4000}"
HEAVY_BG_TOTAL="${HEAVY_BG_TOTAL:-0}"
HEAVY_BG_UIDS="${HEAVY_BG_UIDS:-0}"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>      Target Android serial
  --adb <path>           adb binary path
  --duration <seconds>   Duration per scenario (default: ${DURATION_S})
  --cooldown <seconds>   Sleep between scenarios (default: ${COOLDOWN_S})
  --settle <seconds>     Sleep after pinning freq before first run (default: ${SETTLE_S})
  --freq0 <hz>           policy0 fixed freq (default: ${POLICY0_FREQ})
  --freq4 <hz>           policy4 fixed freq (default: ${POLICY4_FREQ})
  --freq6 <hz>           policy6 fixed freq (default: ${POLICY6_FREQ})
  --order <csv>          Scenario order (default: ${ORDER_CSV})
  --output-dir <path>    Explicit output directory
  -h, --help             Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --adb)
      ADB="$2"
      export ADB
      shift 2
      ;;
    --duration)
      DURATION_S="$2"
      shift 2
      ;;
    --cooldown)
      COOLDOWN_S="$2"
      shift 2
      ;;
    --settle)
      SETTLE_S="$2"
      shift 2
      ;;
    --freq0)
      POLICY0_FREQ="$2"
      shift 2
      ;;
    --freq4)
      POLICY4_FREQ="$2"
      shift 2
      ;;
    --freq6)
      POLICY6_FREQ="$2"
      shift 2
      ;;
    --order)
      ORDER_CSV="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

for v in DURATION_S COOLDOWN_S SETTLE_S POLICY0_FREQ POLICY4_FREQ POLICY6_FREQ HEAVY_TRAFFIC_RULES HEAVY_BG_TOTAL HEAVY_BG_UIDS; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

IFS=',' read -r -a SCENARIOS <<< "$ORDER_CSV"
if [[ "${#SCENARIOS[@]}" -ne 3 ]]; then
  echo "ORDER_CSV must contain exactly 3 scenarios" >&2
  exit 1
fi

for scenario in "${SCENARIOS[@]}"; do
  case "$scenario" in
    iprules_off_empty|iprules_on_empty|iprules_on_heavy) ;;
    *)
      echo "unknown scenario in order: $scenario" >&2
      exit 1
      ;;
  esac
done

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

scenario_iprules() {
  case "$1" in
    iprules_off_empty) echo 0 ;;
    iprules_on_empty) echo 1 ;;
    iprules_on_heavy) echo 1 ;;
  esac
}

scenario_traffic_rules() {
  case "$1" in
    iprules_on_heavy) echo "$HEAVY_TRAFFIC_RULES" ;;
    *) echo 0 ;;
  esac
}

scenario_bg_total() {
  case "$1" in
    iprules_on_heavy) echo "$HEAVY_BG_TOTAL" ;;
    *) echo 0 ;;
  esac
}

scenario_bg_uids() {
  case "$1" in
    iprules_on_heavy) echo "$HEAVY_BG_UIDS" ;;
    *) echo 0 ;;
  esac
}

if [[ -z "${ADB:-}" ]]; then
  ADB="$ADB_BIN"
  export ADB
fi

device_preflight

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$IPMOD_DIR/records/perf-fixedfreq-$(timestamp_compact_utc)_${ADB_SERIAL_RESOLVED}"
fi
mkdir -p "$OUTPUT_DIR"
RUNS_DIR="$OUTPUT_DIR/runs"
mkdir -p "$RUNS_DIR"
RESULTS_JSONL="$OUTPUT_DIR/results.jsonl"
SUMMARY_JSON="$OUTPUT_DIR/summary.json"
PLAN_JSON="$OUTPUT_DIR/plan.json"
CONTROLLER_LOG="$OUTPUT_DIR/controller.log"

log() {
  local ts
  ts="$(timestamp_utc)"
  printf '[%s] %s\n' "$ts" "$*" | tee -a "$CONTROLLER_LOG"
}

capture_device_snapshot() {
  local label="$1"
  local path="$OUTPUT_DIR/${label}.txt"
  adb_su "
echo timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
for p in /sys/devices/system/cpu/cpufreq/policy0 /sys/devices/system/cpu/cpufreq/policy4 /sys/devices/system/cpu/cpufreq/policy6; do
  name=\$(basename \"\$p\")
  echo === \$name ===
  for f in scaling_governor scaling_cur_freq scaling_min_freq scaling_max_freq; do
    if [ -e \"\$p/\$f\" ]; then
      printf '%s=' \"\$f\"
      cat \"\$p/\$f\"
    fi
  done
done
echo --- thermal
dumpsys thermalservice 2>/dev/null | sed -n '/Thermal Status:/,/Current cooling devices from HAL:/p'
echo --- battery
dumpsys battery 2>/dev/null | sed -n '1,80p'
" >"$path"
}

ORIG_POLICY0_GOV="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor' | tr -d '\r\n')"
ORIG_POLICY0_MIN="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq' | tr -d '\r\n')"
ORIG_POLICY0_MAX="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq' | tr -d '\r\n')"
ORIG_POLICY4_GOV="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy4/scaling_governor' | tr -d '\r\n')"
ORIG_POLICY4_MIN="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq' | tr -d '\r\n')"
ORIG_POLICY4_MAX="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy4/scaling_max_freq' | tr -d '\r\n')"
ORIG_POLICY6_GOV="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy6/scaling_governor' | tr -d '\r\n')"
ORIG_POLICY6_MIN="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy6/scaling_min_freq' | tr -d '\r\n')"
ORIG_POLICY6_MAX="$(adb_su 'cat /sys/devices/system/cpu/cpufreq/policy6/scaling_max_freq' | tr -d '\r\n')"

python3 - "$PLAN_JSON" <<PY
import json
from pathlib import Path
payload = {
  "adb_serial": "${ADB_SERIAL_RESOLVED}",
  "duration_s": ${DURATION_S},
  "cooldown_s": ${COOLDOWN_S},
  "settle_s": ${SETTLE_S},
  "order_csv": "${ORDER_CSV}",
  "fixed_freqs": {
    "policy0": ${POLICY0_FREQ},
    "policy4": ${POLICY4_FREQ},
    "policy6": ${POLICY6_FREQ},
  },
  "original": {
    "policy0": {"governor": "${ORIG_POLICY0_GOV}", "min": ${ORIG_POLICY0_MIN}, "max": ${ORIG_POLICY0_MAX}},
    "policy4": {"governor": "${ORIG_POLICY4_GOV}", "min": ${ORIG_POLICY4_MIN}, "max": ${ORIG_POLICY4_MAX}},
    "policy6": {"governor": "${ORIG_POLICY6_GOV}", "min": ${ORIG_POLICY6_MIN}, "max": ${ORIG_POLICY6_MAX}},
  }
}
Path("${PLAN_JSON}").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\\n")
PY

restore_cpu() {
  set +e
  adb_su "
echo ${ORIG_POLICY0_GOV} > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
printf ${ORIG_POLICY0_MIN} > /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq
printf ${ORIG_POLICY0_MAX} > /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq
echo ${ORIG_POLICY4_GOV} > /sys/devices/system/cpu/cpufreq/policy4/scaling_governor
printf ${ORIG_POLICY4_MIN} > /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq
printf ${ORIG_POLICY4_MAX} > /sys/devices/system/cpu/cpufreq/policy4/scaling_max_freq
echo ${ORIG_POLICY6_GOV} > /sys/devices/system/cpu/cpufreq/policy6/scaling_governor
printf ${ORIG_POLICY6_MIN} > /sys/devices/system/cpu/cpufreq/policy6/scaling_min_freq
printf ${ORIG_POLICY6_MAX} > /sys/devices/system/cpu/cpufreq/policy6/scaling_max_freq
" >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  restore_cpu
  capture_device_snapshot "snapshot_restored"
  if [[ $rc -eq 0 ]]; then
    log "completed output_dir=$OUTPUT_DIR"
  else
    log "aborted rc=$rc output_dir=$OUTPUT_DIR"
  fi
}
trap cleanup EXIT

log "pinning frequencies: policy0=${POLICY0_FREQ} policy4=${POLICY4_FREQ} policy6=${POLICY6_FREQ}"
capture_device_snapshot "snapshot_before_pin"
adb_su "
echo performance > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
printf ${POLICY0_FREQ} > /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq
printf ${POLICY0_FREQ} > /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq
echo performance > /sys/devices/system/cpu/cpufreq/policy4/scaling_governor
printf ${POLICY4_FREQ} > /sys/devices/system/cpu/cpufreq/policy4/scaling_max_freq
printf ${POLICY4_FREQ} > /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq
echo performance > /sys/devices/system/cpu/cpufreq/policy6/scaling_governor
printf ${POLICY6_FREQ} > /sys/devices/system/cpu/cpufreq/policy6/scaling_max_freq
printf ${POLICY6_FREQ} > /sys/devices/system/cpu/cpufreq/policy6/scaling_min_freq
" >/dev/null
sleep "$SETTLE_S"
capture_device_snapshot "snapshot_after_pin"

verify_policy() {
  local policy="$1"
  local target="$2"
  local gov cur min max
  gov="$(adb_su "cat /sys/devices/system/cpu/cpufreq/${policy}/scaling_governor" | tr -d '\r\n')"
  cur="$(adb_su "cat /sys/devices/system/cpu/cpufreq/${policy}/scaling_cur_freq" | tr -d '\r\n')"
  min="$(adb_su "cat /sys/devices/system/cpu/cpufreq/${policy}/scaling_min_freq" | tr -d '\r\n')"
  max="$(adb_su "cat /sys/devices/system/cpu/cpufreq/${policy}/scaling_max_freq" | tr -d '\r\n')"
  if [[ "$gov" != "performance" || "$cur" != "$target" || "$min" != "$target" || "$max" != "$target" ]]; then
    echo "failed to pin ${policy}: gov=$gov cur=$cur min=$min max=$max target=$target" >&2
    exit 1
  fi
}

verify_policy policy0 "$POLICY0_FREQ"
verify_policy policy4 "$POLICY4_FREQ"
verify_policy policy6 "$POLICY6_FREQ"

run_scenario() {
  local scenario="$1"
  local log_file="$RUNS_DIR/${scenario}_${DURATION_S}s.log"
  local iprules traffic_rules bg_total bg_uids result_json
  iprules="$(scenario_iprules "$scenario")"
  traffic_rules="$(scenario_traffic_rules "$scenario")"
  bg_total="$(scenario_bg_total "$scenario")"
  bg_uids="$(scenario_bg_uids "$scenario")"

  capture_device_snapshot "before_${scenario}_${DURATION_S}s"
  log "running scenario=$scenario duration=${DURATION_S}s iprules=$iprules traffic_rules=$traffic_rules"

  env \
    ADB="$ADB" \
    ADB_SERIAL="$ADB_SERIAL_RESOLVED" \
    IPTEST_PERF_SECONDS="$DURATION_S" \
    IPTEST_PERF_LOAD_MODE="$IPTEST_PERF_LOAD_MODE" \
    IPTEST_PERF_COMPARE=0 \
    IPTEST_PERF_SINGLE_IPRULES="$iprules" \
    IPTEST_PERF_TRAFFIC_RULES="$traffic_rules" \
    IPTEST_PERF_BG_TOTAL="$bg_total" \
    IPTEST_PERF_BG_UIDS="$bg_uids" \
    IPTEST_PERF_MIX_WORKERS="$IPTEST_PERF_MIX_WORKERS" \
    IPTEST_PERF_MIX_CONN_BYTES="$IPTEST_PERF_MIX_CONN_BYTES" \
    IPTEST_PERF_MIX_HOST_COUNT="$IPTEST_PERF_MIX_HOST_COUNT" \
    IPTEST_PERF_MIX_PEER_COUNT="$IPTEST_PERF_MIX_PEER_COUNT" \
    IPTEST_PERF_MIX_PORT_COUNT="$IPTEST_PERF_MIX_PORT_COUNT" \
    bash "$RUNNER" --skip-deploy --profile perf >"$log_file" 2>&1

  result_json="$(python3 - "$log_file" <<'PY'
import json
import sys
from pathlib import Path

line = ""
for raw in Path(sys.argv[1]).read_text().splitlines():
    if raw.startswith("PERF_RESULT_JSON "):
        line = raw[len("PERF_RESULT_JSON "):]
if not line:
    raise SystemExit("missing PERF_RESULT_JSON")
print(json.dumps(json.loads(line), ensure_ascii=False, separators=(",", ":")))
PY
)"

  python3 - "$RESULTS_JSONL" "$scenario" "$DURATION_S" "$result_json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
scenario = sys.argv[2]
duration_s = int(sys.argv[3])
row = json.loads(sys.argv[4])
row["scenario"] = scenario
row["duration_s"] = duration_s
row["rate_mib_s"] = row["bytes"] / duration_s / 1024 / 1024
row["conn_per_s"] = row.get("connections", 0) / duration_s
row["samples_per_s"] = row["samples"] / duration_s
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
PY

  capture_device_snapshot "after_${scenario}_${DURATION_S}s"
  log "completed scenario=$scenario log=$log_file"
}

for scenario in "${SCENARIOS[@]}"; do
  run_scenario "$scenario"
  sleep "$COOLDOWN_S"
done

python3 - "$RESULTS_JSONL" "$SUMMARY_JSON" <<'PY'
import json
import sys
from pathlib import Path

rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
summary = {"rows": rows}
Path(sys.argv[2]).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
for row in rows:
    lat = row["latency_us"]
    print(
        f"{row['scenario']}: rate={row['rate_mib_s']:.4f}MiB/s "
        f"conn/s={row['conn_per_s']:.4f} samples/s={row['samples_per_s']:.4f} "
        f"avg={lat['avg']} p50={lat['p50']} p95={lat['p95']} p99={lat['p99']} max={lat['max']}"
    )
PY

echo "output_dir=$OUTPUT_DIR"
