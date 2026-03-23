#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

RUNNER="$IPMOD_DIR/neper_perf_3way.sh"
SUMMARIZER="$IPMOD_DIR/tools/summarize_neper_perf_3way.py"

ROUNDS_PER_SCENARIO="${ROUNDS_PER_SCENARIO:-5}"
DURATION_S="${DURATION_S:-30}"
WARMUP_S="${WARMUP_S:-10}"
COOLDOWN_JOB_S="${COOLDOWN_JOB_S:-10}"
SEED="${SEED:-20260322}"

THREADS="${THREADS:-8}"
FLOWS="${FLOWS:-1024}"
BYTES="${BYTES:-1}"
NUM_PORTS="${NUM_PORTS:-16}"
CLIENT_UID="${CLIENT_UID:-2000}"
LOCAL_HOST_COUNT="${LOCAL_HOST_COUNT:-1}"
LOCAL_HOST_BASE_OCTET="${LOCAL_HOST_BASE_OCTET:-101}"
PERFMETRICS="${PERFMETRICS:-0}"

OUTPUT_DIR=""

usage() {
  cat <<EOF
Usage: $0 [options]

Runs each scenario (off/2k/4k) as an independent job (fresh RESETALL + warmup),
then summarizes mean/CV across jobs. This avoids intra-run order bias.

Options:
  --serial <serial>              Target Android serial (or set ADB_SERIAL)
  --adb <path>                   adb binary path (or set ADB)
  --rounds-per-scenario <n>      Repeats per scenario (default: ${ROUNDS_PER_SCENARIO})
  --seconds <n>                  Per-job duration (default: ${DURATION_S})
  --warmup <n>                   Warmup seconds per job (default: ${WARMUP_S})
  --cooldown-job <n>             Sleep between jobs (default: ${COOLDOWN_JOB_S})
  --seed <n>                     Deterministic shuffle seed (default: ${SEED})
  --threads <n>                  neper threads (default: ${THREADS})
  --flows <n>                    neper flows (default: ${FLOWS})
  --bytes <n>                    tcp_crr request/response bytes (default: ${BYTES})
  --num-ports <n>                tcp_crr num ports (default: ${NUM_PORTS})
  --uid <uid>                    Client UID (default: ${CLIENT_UID})
  --local-host-count <n>         Client bind IP pool size (default: ${LOCAL_HOST_COUNT})
  --local-host-base-octet <n>    Extra host IPs start at x.x.x.<n> (default: ${LOCAL_HOST_BASE_OCTET})
  --perfmetrics <0|1>            Toggle PERFMETRICS during the run (default: ${PERFMETRICS})
  --output-dir <path>            Explicit output directory
  -h, --help                     Show help
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
    --rounds-per-scenario)
      ROUNDS_PER_SCENARIO="$2"
      shift 2
      ;;
    --seconds)
      DURATION_S="$2"
      shift 2
      ;;
    --warmup)
      WARMUP_S="$2"
      shift 2
      ;;
    --cooldown-job)
      COOLDOWN_JOB_S="$2"
      shift 2
      ;;
    --seed)
      SEED="$2"
      shift 2
      ;;
    --threads)
      THREADS="$2"
      shift 2
      ;;
    --flows)
      FLOWS="$2"
      shift 2
      ;;
    --bytes)
      BYTES="$2"
      shift 2
      ;;
    --num-ports)
      NUM_PORTS="$2"
      shift 2
      ;;
    --uid)
      CLIENT_UID="$2"
      shift 2
      ;;
    --local-host-count)
      LOCAL_HOST_COUNT="$2"
      shift 2
      ;;
    --local-host-base-octet)
      LOCAL_HOST_BASE_OCTET="$2"
      shift 2
      ;;
    --perfmetrics)
      PERFMETRICS="$2"
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

for v in ROUNDS_PER_SCENARIO DURATION_S WARMUP_S COOLDOWN_JOB_S SEED THREADS FLOWS BYTES NUM_PORTS CLIENT_UID LOCAL_HOST_COUNT LOCAL_HOST_BASE_OCTET PERFMETRICS; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done
if [[ "$ROUNDS_PER_SCENARIO" -lt 1 ]]; then
  echo "ROUNDS_PER_SCENARIO must be >= 1" >&2
  exit 1
fi

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

serial="${ADB_SERIAL:-unknown}"
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$IPMOD_DIR/records/neper-perf-scenario-matrix-$(timestamp_compact_utc)_${serial}"
fi

mkdir -p "$OUTPUT_DIR"
RUNS_TXT="$OUTPUT_DIR/runs.txt"
SUMMARY_TXT="$OUTPUT_DIR/summary.txt"
CONTROLLER_LOG="$OUTPUT_DIR/controller.log"
PLAN_JSON="$OUTPUT_DIR/plan.json"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$CONTROLLER_LOG"
}

python3 - "$PLAN_JSON" <<PY
import json
from pathlib import Path
payload = {
  "adb_serial": "${ADB_SERIAL:-}",
  "rounds_per_scenario": ${ROUNDS_PER_SCENARIO},
  "seconds": ${DURATION_S},
  "warmup": ${WARMUP_S},
  "cooldown_job": ${COOLDOWN_JOB_S},
  "seed": ${SEED},
  "threads": ${THREADS},
  "flows": ${FLOWS},
  "bytes": ${BYTES},
  "num_ports": ${NUM_PORTS},
  "uid": ${CLIENT_UID},
  "local_host_count": ${LOCAL_HOST_COUNT},
  "local_host_base_octet": ${LOCAL_HOST_BASE_OCTET},
  "perfmetrics": ${PERFMETRICS},
}
Path("${PLAN_JSON}").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\\n")
PY

touch "$RUNS_TXT"

# Build job list and shuffle deterministically.
jobs_csv="$(
  python3 - "$ROUNDS_PER_SCENARIO" "$SEED" <<'PY'
import random
import sys

n = int(sys.argv[1])
seed = int(sys.argv[2])

jobs = []
for _ in range(n):
  jobs += ["off", "2k", "4k"]

rng = random.Random(seed)
rng.shuffle(jobs)
print(",".join(jobs))
PY
)"

IFS=',' read -r -a jobs <<< "$jobs_csv"
log "jobs=${#jobs[@]} rounds_per_scenario=$ROUNDS_PER_SCENARIO seed=$SEED"

run_dirs=()
idx=0
total="${#jobs[@]}"
for scenario in "${jobs[@]}"; do
  idx=$((idx + 1))
  log "job $idx/$total: scenario=$scenario start"
  job_log="$OUTPUT_DIR/job_${idx}_${scenario}.log"

  runner_cmd=(
    bash "$RUNNER"
    --scenario "$scenario"
    --seconds "$DURATION_S"
    --warmup "$WARMUP_S"
    --cooldown 0
    --threads "$THREADS"
    --flows "$FLOWS"
    --bytes "$BYTES"
    --num-ports "$NUM_PORTS"
    --uid "$CLIENT_UID"
    --local-host-count "$LOCAL_HOST_COUNT"
    --local-host-base-octet "$LOCAL_HOST_BASE_OCTET"
    --perfmetrics "$PERFMETRICS"
  )
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    runner_cmd+=(--serial "$ADB_SERIAL")
  fi
  if [[ -n "${ADB:-}" ]]; then
    runner_cmd+=(--adb "$ADB")
  fi

  set +e
  "${runner_cmd[@]}" 2>&1 | tee "$job_log"
  rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" -ne 0 ]]; then
    log "job $idx/$total: FAILED rc=$rc (see $job_log)"
    exit "$rc"
  fi

  records_dir="$(sed -n 's/^OK records_dir=//p' "$job_log" | tail -n 1)"
  if [[ -z "$records_dir" ]]; then
    log "job $idx/$total: FAILED to parse records_dir (see $job_log)"
    exit 2
  fi

  log "job $idx/$total: OK records_dir=$records_dir"
  echo "$records_dir" >>"$RUNS_TXT"
  run_dirs+=("$records_dir")

  if [[ "$COOLDOWN_JOB_S" -gt 0 && "$idx" -lt "$total" ]]; then
    log "job $idx/$total: cooldown_job ${COOLDOWN_JOB_S}s"
    sleep "$COOLDOWN_JOB_S"
  fi
done

log "summarize: runs=${#run_dirs[@]}"
python3 "$SUMMARIZER" "${run_dirs[@]}" | tee "$SUMMARY_TXT"

log "done: output_dir=$OUTPUT_DIR"
echo "OK output_dir=$OUTPUT_DIR"

