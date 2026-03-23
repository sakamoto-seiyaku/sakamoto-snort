#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

RUNNER="$IPMOD_DIR/neper_perf_3way.sh"
SUMMARIZER="$IPMOD_DIR/tools/summarize_neper_perf_3way.py"

ROUNDS="${ROUNDS:-5}"
DURATION_S="${DURATION_S:-30}"
WARMUP_S="${WARMUP_S:-10}"
COOLDOWN_S="${COOLDOWN_S:-30}"
COOLDOWN_ROUND_S="${COOLDOWN_ROUND_S:-0}"

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

Options:
  --serial <serial>           Target Android serial (or set ADB_SERIAL)
  --adb <path>                adb binary path (or set ADB)
  --rounds <n>                Number of independent 3-way runs (default: ${ROUNDS})
  --seconds <n>               Per-scenario duration (default: ${DURATION_S})
  --warmup <n>                Warmup seconds (default: ${WARMUP_S})
  --cooldown <n>              Cooldown between scenarios (default: ${COOLDOWN_S})
  --cooldown-round <n>        Cooldown between rounds (default: ${COOLDOWN_ROUND_S})
  --threads <n>               neper threads (default: ${THREADS})
  --flows <n>                 neper flows (default: ${FLOWS})
  --bytes <n>                 tcp_crr request/response bytes (default: ${BYTES})
  --num-ports <n>             tcp_crr num ports (default: ${NUM_PORTS})
  --uid <uid>                 Client UID (default: ${CLIENT_UID})
  --local-host-count <n>      Client bind IP pool size (default: ${LOCAL_HOST_COUNT})
  --local-host-base-octet <n> Extra host IPs start at x.x.x.<n> (default: ${LOCAL_HOST_BASE_OCTET})
  --perfmetrics <0|1>         Toggle PERFMETRICS during the run (default: ${PERFMETRICS})
  --output-dir <path>         Explicit output directory
  -h, --help                  Show help
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
    --rounds)
      ROUNDS="$2"
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
    --cooldown)
      COOLDOWN_S="$2"
      shift 2
      ;;
    --cooldown-round)
      COOLDOWN_ROUND_S="$2"
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

for v in ROUNDS DURATION_S WARMUP_S COOLDOWN_S COOLDOWN_ROUND_S THREADS FLOWS BYTES NUM_PORTS CLIENT_UID LOCAL_HOST_COUNT LOCAL_HOST_BASE_OCTET PERFMETRICS; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done
if [[ "$ROUNDS" -lt 1 ]]; then
  echo "ROUNDS must be >= 1" >&2
  exit 1
fi

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

serial="${ADB_SERIAL:-unknown}"
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$IPMOD_DIR/records/neper-perf-matrix-$(timestamp_compact_utc)_${serial}"
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
  "rounds": ${ROUNDS},
  "seconds": ${DURATION_S},
  "warmup": ${WARMUP_S},
  "cooldown": ${COOLDOWN_S},
  "cooldown_round": ${COOLDOWN_ROUND_S},
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

run_dirs=()
for ((i = 1; i <= ROUNDS; i++)); do
  log "round $i/$ROUNDS: start"
  round_log="$OUTPUT_DIR/round_${i}.log"

  runner_cmd=(
    bash "$RUNNER"
    --seconds "$DURATION_S"
    --warmup "$WARMUP_S"
    --cooldown "$COOLDOWN_S"
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
  "${runner_cmd[@]}" 2>&1 | tee "$round_log"
  rc=${PIPESTATUS[0]}
  set -e

  if [[ "$rc" -ne 0 ]]; then
    log "round $i/$ROUNDS: FAILED rc=$rc (see $round_log)"
    exit "$rc"
  fi

  records_dir="$(sed -n 's/^OK records_dir=//p' "$round_log" | tail -n 1)"
  if [[ -z "$records_dir" ]]; then
    log "round $i/$ROUNDS: FAILED to parse records_dir (see $round_log)"
    exit 2
  fi
  log "round $i/$ROUNDS: OK records_dir=$records_dir"
  echo "$records_dir" >>"$RUNS_TXT"
  run_dirs+=("$records_dir")

  if [[ "$COOLDOWN_ROUND_S" -gt 0 && "$i" -lt "$ROUNDS" ]]; then
    log "round $i/$ROUNDS: cooldown_round ${COOLDOWN_ROUND_S}s"
    sleep "$COOLDOWN_ROUND_S"
  fi
done

log "summarize: runs=${#run_dirs[@]}"
python3 "$SUMMARIZER" "${run_dirs[@]}" | tee "$SUMMARY_TXT"

log "done: output_dir=$OUTPUT_DIR"
echo "OK output_dir=$OUTPUT_DIR"
