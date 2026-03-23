#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"
RUNNER="$IPMOD_DIR/run.sh"
SUMMARIZER="$IPMOD_DIR/perf_overnight_summarize.py"

RUN_HOURS="${RUN_HOURS:-7}"
WARMUP_SECONDS="${WARMUP_SECONDS:-60}"
DURATIONS_CSV="${DURATIONS_CSV:-30,90,180,300}"
COOLDOWN_JOB_SECONDS="${COOLDOWN_JOB_SECONDS:-10}"
COOLDOWN_BLOCK_SECONDS="${COOLDOWN_BLOCK_SECONDS:-60}"
ESTIMATED_OVERHEAD_SECONDS="${ESTIMATED_OVERHEAD_SECONDS:-150}"
HEAVY_TRAFFIC_RULES="${HEAVY_TRAFFIC_RULES:-4000}"
HEAVY_BG_TOTAL="${HEAVY_BG_TOTAL:-0}"
HEAVY_BG_UIDS="${HEAVY_BG_UIDS:-0}"
MIRROR_TO_DEVICE="${MIRROR_TO_DEVICE:-1}"
DO_DEPLOY="${DO_DEPLOY:-0}"
STOP_ON_ERROR="${STOP_ON_ERROR:-1}"
ORDER_SEED="${ORDER_SEED:-20260320}"
OUTPUT_DIR=""

IPTEST_PERF_LOAD_MODE="${IPTEST_PERF_LOAD_MODE:-mix}"
IPTEST_PERF_MIX_WORKERS="${IPTEST_PERF_MIX_WORKERS:-16}"
IPTEST_PERF_MIX_CONN_BYTES="${IPTEST_PERF_MIX_CONN_BYTES:-4096}"
IPTEST_PERF_MIX_HOST_COUNT="${IPTEST_PERF_MIX_HOST_COUNT:-4}"
IPTEST_PERF_MIX_PEER_COUNT="${IPTEST_PERF_MIX_PEER_COUNT:-16}"
IPTEST_PERF_MIX_PORT_COUNT="${IPTEST_PERF_MIX_PORT_COUNT:-8}"

SCENARIOS=("iprules_off_empty" "iprules_on_empty" "iprules_on_heavy")

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>           Target Android serial (or set ADB_SERIAL)
  --adb <path>                adb binary path (or set ADB)
  --hours <n>                 Total budget in hours (default: ${RUN_HOURS})
  --warmup-seconds <n>        Warm-up duration per scenario (default: ${WARMUP_SECONDS})
  --durations <csv>           Main durations in seconds (default: ${DURATIONS_CSV})
  --output-dir <path>         Explicit output directory
  --cooldown-job <n>          Sleep between jobs (default: ${COOLDOWN_JOB_SECONDS})
  --cooldown-block <n>        Sleep between blocks (default: ${COOLDOWN_BLOCK_SECONDS})
  --seed <n>                  Deterministic shuffle seed (default: ${ORDER_SEED})
  --deploy                    Run deploy before starting
  --no-device-mirror          Do not mirror status/results to /data/local/tmp
  --continue-on-error         Keep going after a failed job
  -h, --help                  Show help

Environment knobs:
  IPTEST_PERF_LOAD_MODE
  IPTEST_PERF_MIX_WORKERS
  IPTEST_PERF_MIX_CONN_BYTES
  IPTEST_PERF_MIX_HOST_COUNT
  IPTEST_PERF_MIX_PEER_COUNT
  IPTEST_PERF_MIX_PORT_COUNT
  HEAVY_TRAFFIC_RULES
  HEAVY_BG_TOTAL
  HEAVY_BG_UIDS
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="${2:?missing serial}"
      export ADB_SERIAL
      shift 2
      ;;
    --adb)
      ADB="${2:?missing adb path}"
      export ADB
      shift 2
      ;;
    --hours)
      RUN_HOURS="${2:?missing hours}"
      shift 2
      ;;
    --warmup-seconds)
      WARMUP_SECONDS="${2:?missing warmup-seconds}"
      shift 2
      ;;
    --durations)
      DURATIONS_CSV="${2:?missing durations}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing output-dir}"
      shift 2
      ;;
    --cooldown-job)
      COOLDOWN_JOB_SECONDS="${2:?missing cooldown-job}"
      shift 2
      ;;
    --cooldown-block)
      COOLDOWN_BLOCK_SECONDS="${2:?missing cooldown-block}"
      shift 2
      ;;
    --seed)
      ORDER_SEED="${2:?missing seed}"
      shift 2
      ;;
    --deploy)
      DO_DEPLOY=1
      shift
      ;;
    --no-device-mirror)
      MIRROR_TO_DEVICE=0
      shift
      ;;
    --continue-on-error)
      STOP_ON_ERROR=0
      shift
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

if [[ -z "${ADB:-}" ]]; then
  if [[ -x "$HOME/.local/android/platform-tools/adb" ]]; then
    ADB="$HOME/.local/android/platform-tools/adb"
  else
    ADB="$(command -v adb)"
  fi
  export ADB
fi

if [[ -z "${ADB_SERIAL:-}" ]]; then
  echo "ADB_SERIAL is required" >&2
  exit 1
fi

if ! [[ "$RUN_HOURS" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "RUN_HOURS must be numeric (got: $RUN_HOURS)" >&2
  exit 1
fi

for value_name in WARMUP_SECONDS COOLDOWN_JOB_SECONDS COOLDOWN_BLOCK_SECONDS ESTIMATED_OVERHEAD_SECONDS HEAVY_TRAFFIC_RULES HEAVY_BG_TOTAL HEAVY_BG_UIDS ORDER_SEED; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$value_name must be a non-negative integer (got: $value)" >&2
    exit 1
  fi
done

IFS=',' read -r -a DURATIONS <<< "$DURATIONS_CSV"
if [[ "${#DURATIONS[@]}" -lt 1 ]]; then
  echo "at least one duration is required" >&2
  exit 1
fi
for duration in "${DURATIONS[@]}"; do
  if ! [[ "$duration" =~ ^[0-9]+$ && "$duration" -gt 0 ]]; then
    echo "invalid duration in DURATIONS_CSV: $duration" >&2
    exit 1
  fi
done

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

SCENARIO_IPRULES_iprules_off_empty=0
SCENARIO_TRAFFIC_RULES_iprules_off_empty=0
SCENARIO_BG_TOTAL_iprules_off_empty=0
SCENARIO_BG_UIDS_iprules_off_empty=0

SCENARIO_IPRULES_iprules_on_empty=1
SCENARIO_TRAFFIC_RULES_iprules_on_empty=0
SCENARIO_BG_TOTAL_iprules_on_empty=0
SCENARIO_BG_UIDS_iprules_on_empty=0

SCENARIO_IPRULES_iprules_on_heavy=1
SCENARIO_TRAFFIC_RULES_iprules_on_heavy="$HEAVY_TRAFFIC_RULES"
SCENARIO_BG_TOTAL_iprules_on_heavy="$HEAVY_BG_TOTAL"
SCENARIO_BG_UIDS_iprules_on_heavy="$HEAVY_BG_UIDS"

scenario_value() {
  local field="$1"
  local scenario="$2"
  local var_name="SCENARIO_${field}_${scenario}"
  printf '%s\n' "${!var_name}"
}

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$IPMOD_DIR/records/perf-overnight-$(timestamp_compact_utc)_${ADB_SERIAL}"
fi

RUNS_DIR="$OUTPUT_DIR/runs"
RESULTS_JSONL="$OUTPUT_DIR/results.jsonl"
WARMUP_JSONL="$OUTPUT_DIR/warmup_results.jsonl"
SUMMARY_JSON="$OUTPUT_DIR/summary_partial.json"
SUMMARY_TEXT="$OUTPUT_DIR/summary_partial.txt"
STATUS_JSON="$OUTPUT_DIR/status.json"
PLAN_JSON="$OUTPUT_DIR/plan.json"
HOST_LOG="$OUTPUT_DIR/controller.log"
DEVICE_PREFIX="/data/local/tmp/ip_perf_overnight_$(basename "$OUTPUT_DIR")"
DEVICE_STATUS_JSON="${DEVICE_PREFIX}_status.json"
DEVICE_RESULTS_JSONL="${DEVICE_PREFIX}_results.jsonl"

mkdir -p "$RUNS_DIR"
touch "$RESULTS_JSONL" "$WARMUP_JSONL"

GLOBAL_LOCK="/tmp/ip_perf_overnight_${ADB_SERIAL}.lock"

exec 9>"$GLOBAL_LOCK"
if ! flock -n 9; then
  echo "another overnight run is already active for device $ADB_SERIAL" >&2
  exit 1
fi

log() {
  local ts
  ts="$(timestamp_utc)"
  printf '[%s] %s\n' "$ts" "$*" | tee -a "$HOST_LOG"
}

mirror_to_device() {
  [[ "$MIRROR_TO_DEVICE" -eq 1 ]] || return 0
  "$ADB" -s "$ADB_SERIAL" wait-for-device >/dev/null 2>&1 || return 0
  "$ADB" -s "$ADB_SERIAL" push "$STATUS_JSON" "$DEVICE_STATUS_JSON" >/dev/null 2>&1 || true
  "$ADB" -s "$ADB_SERIAL" push "$RESULTS_JSONL" "$DEVICE_RESULTS_JSONL" >/dev/null 2>&1 || true
}

write_status() {
  local state="$1"
  local message="$2"
  local phase="${3:-main}"
  local block_id="${4:-0}"
  local job_index="${5:-0}"
  local scenario="${6:-}"
  local duration_s="${7:-0}"

  python3 - "$STATUS_JSON" "$state" "$message" "$phase" "$block_id" "$job_index" "$scenario" "$duration_s" "$START_TS" "$DEADLINE_TS" "$RESULTS_JSONL" "$WARMUP_JSONL" <<'PY'
import json
import sys
from pathlib import Path

status_path = Path(sys.argv[1])
state = sys.argv[2]
message = sys.argv[3]
phase = sys.argv[4]
block_id = int(sys.argv[5])
job_index = int(sys.argv[6])
scenario = sys.argv[7]
duration_s = int(sys.argv[8])
start_ts = sys.argv[9]
deadline_ts = sys.argv[10]
results_path = Path(sys.argv[11])
warmup_path = Path(sys.argv[12])

def count_lines(path):
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text().splitlines() if line.strip())

payload = {
    "state": state,
    "message": message,
    "phase": phase,
    "block_id": block_id,
    "job_index": job_index,
    "scenario": scenario,
    "duration_s": duration_s,
    "start_ts": start_ts,
    "deadline_ts": deadline_ts,
    "main_runs_completed": count_lines(results_path),
    "warmup_runs_completed": count_lines(warmup_path),
}
status_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
PY
  mirror_to_device
}

summarize_partial() {
  python3 "$SUMMARIZER" \
    --results "$RESULTS_JSONL" \
    --summary-json "$SUMMARY_JSON" \
    --summary-text "$SUMMARY_TEXT"
  mirror_to_device
}

job_timeout_for_duration() {
  local duration_s="$1"
  printf '%s\n' "$((duration_s + ESTIMATED_OVERHEAD_SECONDS))"
}

wait_for_boot_completed() {
  local deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    if "$ADB" -s "$ADB_SERIAL" wait-for-device >/dev/null 2>&1; then
      local boot
      boot="$("$ADB" -s "$ADB_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
      if [[ "$boot" == "1" ]]; then
        return 0
      fi
    fi
    sleep 5
  done
  return 1
}

record_job_result() {
  local source_json="$1"
  local sink_jsonl="$2"
  local scenario="$3"
  local duration_s="$4"
  local phase="$5"
  local block_id="$6"
  local job_index="$7"
  local log_file="$8"
  local start_ts="$9"
  local end_ts="${10}"

  python3 - "$source_json" "$sink_jsonl" "$scenario" "$duration_s" "$phase" "$block_id" "$job_index" "$log_file" "$start_ts" "$end_ts" <<'PY'
import json
import sys
from pathlib import Path

row = json.loads(sys.argv[1])
sink = Path(sys.argv[2])
scenario = sys.argv[3]
duration_s = int(sys.argv[4])
phase = sys.argv[5]
block_id = int(sys.argv[6])
job_index = int(sys.argv[7])
log_file = sys.argv[8]
start_ts = sys.argv[9]
end_ts = sys.argv[10]

row["scenario"] = scenario
row["duration_s"] = duration_s
row["phase"] = phase
row["block_id"] = block_id
row["job_index"] = job_index
row["log_file"] = log_file
row["start_ts"] = start_ts
row["end_ts"] = end_ts
row["rate_mib_s"] = row["bytes"] / duration_s / 1024 / 1024
row["conn_per_s"] = row.get("connections", 0) / duration_s
row["samples_per_s"] = row["samples"] / duration_s

with sink.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
PY
}

extract_perf_result_json() {
  local log_file="$1"
  python3 - "$log_file" <<'PY'
import json
import sys
from pathlib import Path

line = ""
for raw in Path(sys.argv[1]).read_text().splitlines():
    if raw.startswith("PERF_RESULT_JSON "):
        line = raw[len("PERF_RESULT_JSON "):]
if not line:
    raise SystemExit(1)
row = json.loads(line)
print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
PY
}

run_one_job() {
  local scenario="$1"
  local duration_s="$2"
  local phase="$3"
  local block_id="$4"
  local job_index="$5"
  local sink_jsonl="$6"

  local iprules traffic_rules bg_total bg_uids
  iprules="$(scenario_value IPRULES "$scenario")"
  traffic_rules="$(scenario_value TRAFFIC_RULES "$scenario")"
  bg_total="$(scenario_value BG_TOTAL "$scenario")"
  bg_uids="$(scenario_value BG_UIDS "$scenario")"

  local tag
  tag="$(printf '%04d_%s_%ss' "$job_index" "$scenario" "$duration_s")"
  local log_file="$RUNS_DIR/${tag}.log"
  local start_ts end_ts timeout_s result_json

  start_ts="$(timestamp_utc)"
  timeout_s="$(job_timeout_for_duration "$duration_s")"
  write_status "running" "running $scenario ${duration_s}s" "$phase" "$block_id" "$job_index" "$scenario" "$duration_s"
  log "start phase=$phase block=$block_id job=$job_index scenario=$scenario duration=${duration_s}s timeout=${timeout_s}s"

  if ! wait_for_boot_completed; then
    log "device not ready before job $tag"
    return 1
  fi

  set +e
  env \
    ADB="$ADB" \
    ADB_SERIAL="$ADB_SERIAL" \
    IPTEST_PERF_SECONDS="$duration_s" \
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
    timeout "$timeout_s" bash "$RUNNER" --skip-deploy --profile perf >"$log_file" 2>&1
  local rc=$?
  set -e

  end_ts="$(timestamp_utc)"

  if [[ $rc -ne 0 ]]; then
    log "job failed rc=$rc tag=$tag log=$log_file"
    tail -n 80 "$log_file" | tee -a "$HOST_LOG" >/dev/null || true
    write_status "failed" "job failed rc=$rc log=$log_file" "$phase" "$block_id" "$job_index" "$scenario" "$duration_s"
    return "$rc"
  fi

  result_json="$(extract_perf_result_json "$log_file")"
  record_job_result "$result_json" "$sink_jsonl" "$scenario" "$duration_s" "$phase" "$block_id" "$job_index" "$log_file" "$start_ts" "$end_ts"
  if [[ "$phase" == "main" ]]; then
    summarize_partial
  fi
  write_status "idle" "completed $scenario ${duration_s}s" "$phase" "$block_id" "$job_index" "$scenario" "$duration_s"
  log "completed phase=$phase block=$block_id job=$job_index scenario=$scenario duration=${duration_s}s log=$log_file"
  return 0
}

emit_plan() {
  python3 - "$PLAN_JSON" "$ADB_SERIAL" "$RUN_HOURS" "$WARMUP_SECONDS" "$DURATIONS_CSV" "$COOLDOWN_JOB_SECONDS" "$COOLDOWN_BLOCK_SECONDS" "$ORDER_SEED" "$HEAVY_TRAFFIC_RULES" "$HEAVY_BG_TOTAL" "$HEAVY_BG_UIDS" "$IPTEST_PERF_LOAD_MODE" "$IPTEST_PERF_MIX_WORKERS" "$IPTEST_PERF_MIX_CONN_BYTES" "$IPTEST_PERF_MIX_HOST_COUNT" "$IPTEST_PERF_MIX_PEER_COUNT" "$IPTEST_PERF_MIX_PORT_COUNT" "$OUTPUT_DIR" "$START_TS" "$DEADLINE_TS" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "adb_serial": sys.argv[2],
    "run_hours": float(sys.argv[3]),
    "warmup_seconds": int(sys.argv[4]),
    "durations_csv": sys.argv[5],
    "cooldown_job_seconds": int(sys.argv[6]),
    "cooldown_block_seconds": int(sys.argv[7]),
    "order_seed": int(sys.argv[8]),
    "heavy_traffic_rules": int(sys.argv[9]),
    "heavy_bg_total": int(sys.argv[10]),
    "heavy_bg_uids": int(sys.argv[11]),
    "load_mode": sys.argv[12],
    "mix_workers": int(sys.argv[13]),
    "mix_conn_bytes": int(sys.argv[14]),
    "mix_host_count": int(sys.argv[15]),
    "mix_peer_count": int(sys.argv[16]),
    "mix_port_count": int(sys.argv[17]),
    "output_dir": sys.argv[18],
    "start_ts": sys.argv[19],
    "deadline_ts": sys.argv[20],
}
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
PY
}

generate_block_order() {
  local block_id="$1"
  python3 - "$ORDER_SEED" "$block_id" "$DURATIONS_CSV" <<'PY'
import random
import sys

seed = int(sys.argv[1])
block_id = int(sys.argv[2])
durations = [int(item) for item in sys.argv[3].split(",") if item]
scenarios = ["iprules_off_empty", "iprules_on_empty", "iprules_on_heavy"]
pairs = [(scenario, duration) for duration in durations for scenario in scenarios]
rng = random.Random(seed + block_id)
rng.shuffle(pairs)
for scenario, duration in pairs:
    print(f"{scenario},{duration}")
PY
}

remaining_time_s() {
  python3 - "$DEADLINE_EPOCH" <<'PY'
import sys
import time

deadline = float(sys.argv[1])
print(int(deadline - time.time()))
PY
}

cleanup_on_exit() {
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    write_status "completed" "overnight run completed"
    log "overnight run completed output_dir=$OUTPUT_DIR"
  else
    write_status "failed" "overnight run aborted rc=$rc"
    log "overnight run aborted rc=$rc output_dir=$OUTPUT_DIR"
  fi
}

trap cleanup_on_exit EXIT

START_TS="$(timestamp_utc)"
DEADLINE_EPOCH="$(python3 - "$RUN_HOURS" <<'PY'
import sys
import time

hours = float(sys.argv[1])
print(time.time() + hours * 3600.0)
PY
)"
DEADLINE_TS="$(python3 - "$DEADLINE_EPOCH" <<'PY'
import datetime as dt
import sys

deadline = dt.datetime.fromtimestamp(float(sys.argv[1]), tz=dt.timezone.utc)
print(deadline.strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"

emit_plan
summarize_partial
write_status "starting" "overnight run starting"
log "output_dir=$OUTPUT_DIR"
log "adb=$ADB serial=$ADB_SERIAL run_hours=$RUN_HOURS durations=$DURATIONS_CSV load_mode=$IPTEST_PERF_LOAD_MODE"

if [[ "$DO_DEPLOY" -eq 1 ]]; then
  log "deploying once before overnight run"
  bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$ADB_SERIAL" | tee -a "$HOST_LOG"
fi

job_index=0
block_id=0

if [[ "$WARMUP_SECONDS" -gt 0 ]]; then
  for scenario in "${SCENARIOS[@]}"; do
    job_index=$((job_index + 1))
    if ! run_one_job "$scenario" "$WARMUP_SECONDS" "warmup" 0 "$job_index" "$WARMUP_JSONL"; then
      if [[ "$STOP_ON_ERROR" -eq 1 ]]; then
        exit 1
      fi
    fi
    sleep "$COOLDOWN_JOB_SECONDS"
  done
  sleep "$COOLDOWN_BLOCK_SECONDS"
fi

while :; do
  block_id=$((block_id + 1))
  log "starting main block=$block_id"
  mapfile -t block_jobs < <(generate_block_order "$block_id")
  started_any=0

  for entry in "${block_jobs[@]}"; do
    IFS=',' read -r scenario duration_s <<< "$entry"
    local_remaining="$(remaining_time_s)"
    if (( local_remaining <= duration_s + ESTIMATED_OVERHEAD_SECONDS )); then
      log "skip starting new job scenario=$scenario duration=${duration_s}s remaining=${local_remaining}s"
      started_any=0
      break 2
    fi

    job_index=$((job_index + 1))
    started_any=1
    if ! run_one_job "$scenario" "$duration_s" "main" "$block_id" "$job_index" "$RESULTS_JSONL"; then
      if [[ "$STOP_ON_ERROR" -eq 1 ]]; then
        exit 1
      fi
    fi
    sleep "$COOLDOWN_JOB_SECONDS"
  done

  if [[ "$started_any" -eq 0 ]]; then
    break
  fi

  local_remaining="$(remaining_time_s)"
  if (( local_remaining <= COOLDOWN_BLOCK_SECONDS + ESTIMATED_OVERHEAD_SECONDS )); then
    log "deadline near, stop after block=$block_id remaining=${local_remaining}s"
    break
  fi
  sleep "$COOLDOWN_BLOCK_SECONDS"
done
