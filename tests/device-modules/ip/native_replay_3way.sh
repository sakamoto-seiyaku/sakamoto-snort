#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"
RUNNER="$IPMOD_DIR/native_replay_poc.sh"

DO_BUILD=1
DO_DEPLOY=0
DURATION_S="${DURATION_S:-30}"
THREADS="${THREADS:-112}"
TRACE_ENTRIES="${TRACE_ENTRIES:-16384}"
CONN_BYTES="${CONN_BYTES:-256}"
PORT_COUNT="${PORT_COUNT:-16}"
SRC_PORT_SPAN="${SRC_PORT_SPAN:-16384}"
HOST_COUNT="${HOST_COUNT:-8}"
PEER_COUNT="${PEER_COUNT:-16}"
TRACE_SHUFFLE="${TRACE_SHUFFLE:-1}"
TRACE_SEED="${TRACE_SEED:-1}"
HEAVY_TRAFFIC_RULES="${HEAVY_TRAFFIC_RULES:-4000}"
SCENARIO_ORDER="${SCENARIO_ORDER:-iprules_off_empty,iprules_on_empty,iprules_on_heavy}"
OUTPUT_DIR="${OUTPUT_DIR:-}"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>      Target Android serial
  --adb <path>           adb binary path
  --skip-build           Reuse existing build-output/iptest-replay
  --deploy               Run deploy once before the batch
  --seconds <n>          Replay duration per scenario (default: ${DURATION_S})
  --rules <n>            Heavy scenario rule count (default: ${HEAVY_TRAFFIC_RULES})
  --order <csv>          Scenario order (default: ${SCENARIO_ORDER})
  --output-dir <path>    Explicit output directory
  -h, --help             Show help

Scenarios:
  iprules_off_empty      IPRULES=0, empty ruleset
  iprules_on_empty       IPRULES=1, empty ruleset
  iprules_on_heavy       IPRULES=1, mixed would-block rules
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
    --skip-build)
      DO_BUILD=0
      shift
      ;;
    --deploy)
      DO_DEPLOY=1
      shift
      ;;
    --seconds)
      DURATION_S="$2"
      shift 2
      ;;
    --rules)
      HEAVY_TRAFFIC_RULES="$2"
      shift 2
      ;;
    --order)
      SCENARIO_ORDER="$2"
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

for v in DURATION_S THREADS TRACE_ENTRIES CONN_BYTES PORT_COUNT SRC_PORT_SPAN HOST_COUNT PEER_COUNT TRACE_SHUFFLE TRACE_SEED HEAVY_TRAFFIC_RULES; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

IFS=',' read -r -a SCENARIOS <<< "$SCENARIO_ORDER"
if [[ "${#SCENARIOS[@]}" -ne 3 ]]; then
  echo "SCENARIO_ORDER must list exactly 3 scenarios" >&2
  exit 1
fi

scenario_iprules() {
  case "$1" in
    iprules_off_empty) echo 0 ;;
    iprules_on_empty|iprules_on_heavy) echo 1 ;;
    *)
      echo "unknown scenario: $1" >&2
      exit 1
      ;;
  esac
}

scenario_rules() {
  case "$1" in
    iprules_on_heavy) echo "$HEAVY_TRAFFIC_RULES" ;;
    iprules_off_empty|iprules_on_empty) echo 0 ;;
    *)
      echo "unknown scenario: $1" >&2
      exit 1
      ;;
  esac
}

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

if [[ -z "$OUTPUT_DIR" ]]; then
  serial_tag="${ADB_SERIAL:-unknown}"
  OUTPUT_DIR="$IPMOD_DIR/records/native-replay-3way-$(timestamp_compact_utc)_${serial_tag}"
fi
mkdir -p "$OUTPUT_DIR"
RESULTS_JSONL="$OUTPUT_DIR/results.jsonl"
SUMMARY_JSON="$OUTPUT_DIR/summary.json"

if [[ $DO_BUILD -eq 1 ]]; then
  bash "$SNORT_ROOT/dev/dev-build-iptest-replay.sh"
fi

if [[ $DO_DEPLOY -eq 1 ]]; then
  deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    deploy_cmd+=(--serial "$ADB_SERIAL")
  fi
  "${deploy_cmd[@]}"
fi

run_scenario() {
  local scenario="$1"
  local iprules="$2"
  local rules="$3"
  local log_file="$OUTPUT_DIR/${scenario}.log"
  local -a cmd=(
    env
    "DURATION_S=$DURATION_S"
    "THREADS=$THREADS"
    "TRACE_ENTRIES=$TRACE_ENTRIES"
    "CONN_BYTES=$CONN_BYTES"
    "PORT_COUNT=$PORT_COUNT"
    "SRC_PORT_SPAN=$SRC_PORT_SPAN"
    "HOST_COUNT=$HOST_COUNT"
    "PEER_COUNT=$PEER_COUNT"
    "TRACE_SHUFFLE=$TRACE_SHUFFLE"
    "TRACE_SEED=$TRACE_SEED"
    "IPTEST_REPLAY_SINGLE_IPRULES=$iprules"
    "IPTEST_REPLAY_TRAFFIC_RULES=$rules"
    bash
    "$RUNNER"
    --skip-build
    --skip-deploy
  )

  if [[ -n "${ADB_SERIAL:-}" ]]; then
    cmd+=(--serial "$ADB_SERIAL")
  fi
  if [[ -n "${ADB:-}" ]]; then
    cmd+=(--adb "$ADB")
  fi

  echo ""
  echo "=== NATIVE REPLAY SCENARIO: $scenario ==="
  echo "seconds=$DURATION_S iprules=$iprules rules=$rules threads=$THREADS trace_entries=$TRACE_ENTRIES"

  "${cmd[@]}" | tee "$log_file"

  python3 - "$scenario" "$iprules" "$rules" "$log_file" >>"$RESULTS_JSONL" <<'PY'
import json
import pathlib
import sys

scenario = sys.argv[1]
iprules = int(sys.argv[2])
rules = int(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])

replay = None
perf = None
preflight = None
for raw in log_path.read_text().splitlines():
    if raw.startswith("REPLAY_RESULT_JSON "):
        replay = json.loads(raw.split(" ", 1)[1])
    elif raw.startswith("PERF_RESULT_JSON "):
        perf = json.loads(raw.split(" ", 1)[1])
    elif raw.startswith("PREFLIGHT_RESULT_JSON "):
        preflight = json.loads(raw.split(" ", 1)[1])

if replay is None or perf is None or preflight is None:
    raise SystemExit(f"missing JSON markers in {log_path}")

nfq = perf["perf"]["nfq_total_us"]
row = {
    "scenario": scenario,
    "iprules": iprules,
    "traffic_rules": rules,
    "bytes": int(replay["bytes"]),
    "connections": int(replay["connections"]),
    "failures": int(replay["failures"]),
    "threads": int(replay["threads"]),
    "seconds": int(replay["seconds"]),
    "elapsed_ms": int(replay["elapsed_ms"]),
    "trace_entries": int(replay["trace_entries"]),
    "samples": int(nfq["samples"]),
    "latency_us": {
        "min": int(nfq["min"]),
        "avg": int(nfq["avg"]),
        "p50": int(nfq["p50"]),
        "p95": int(nfq["p95"]),
        "p99": int(nfq["p99"]),
        "max": int(nfq["max"]),
    },
    "preflight": preflight.get("summary", {}),
}
print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
PY
}

for scenario in "${SCENARIOS[@]}"; do
  run_scenario "$scenario" "$(scenario_iprules "$scenario")" "$(scenario_rules "$scenario")"
done

python3 - "$RESULTS_JSONL" "$SUMMARY_JSON" "$SCENARIO_ORDER" <<'PY'
import json
import sys
from pathlib import Path

rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
summary_path = Path(sys.argv[2])
order = [item for item in sys.argv[3].split(",") if item]

if len(rows) != len(order):
    raise SystemExit(f"expected {len(order)} rows, got {len(rows)}")

for row in rows:
    row["rate_mib_s"] = row["bytes"] / row["seconds"] / 1024 / 1024

def delta(cur, base):
    if base == 0:
        return None
    return (cur - base) / base * 100.0

by_name = {row["scenario"]: row for row in rows}
off = by_name["iprules_off_empty"]
on_empty = by_name["iprules_on_empty"]
on_heavy = by_name["iprules_on_heavy"]

summary = {
    "scenario_order": order,
    "scenarios": rows,
    "deltas_pct": {
        "empty_on_vs_off": {
            "bytes": delta(on_empty["bytes"], off["bytes"]),
            "connections": delta(on_empty["connections"], off["connections"]),
            "samples": delta(on_empty["samples"], off["samples"]),
            "avg": delta(on_empty["latency_us"]["avg"], off["latency_us"]["avg"]),
            "p95": delta(on_empty["latency_us"]["p95"], off["latency_us"]["p95"]),
            "p99": delta(on_empty["latency_us"]["p99"], off["latency_us"]["p99"]),
        },
        "heavy_vs_empty_on": {
            "bytes": delta(on_heavy["bytes"], on_empty["bytes"]),
            "connections": delta(on_heavy["connections"], on_empty["connections"]),
            "samples": delta(on_heavy["samples"], on_empty["samples"]),
            "avg": delta(on_heavy["latency_us"]["avg"], on_empty["latency_us"]["avg"]),
            "p95": delta(on_heavy["latency_us"]["p95"], on_empty["latency_us"]["p95"]),
            "p99": delta(on_heavy["latency_us"]["p99"], on_empty["latency_us"]["p99"]),
        },
        "heavy_vs_off": {
            "bytes": delta(on_heavy["bytes"], off["bytes"]),
            "connections": delta(on_heavy["connections"], off["connections"]),
            "samples": delta(on_heavy["samples"], off["samples"]),
            "avg": delta(on_heavy["latency_us"]["avg"], off["latency_us"]["avg"]),
            "p95": delta(on_heavy["latency_us"]["p95"], off["latency_us"]["p95"]),
            "p99": delta(on_heavy["latency_us"]["p99"], off["latency_us"]["p99"]),
        },
    },
}
summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

print("")
print("=== NATIVE REPLAY 3-WAY SUMMARY ===")
for row in rows:
    lat = row["latency_us"]
    print(
        f"{row['scenario']}: rate={row['rate_mib_s']:.4f} MiB/s "
        f"conn={row['connections']} samples={row['samples']} "
        f"avg={lat['avg']}us p95={lat['p95']}us p99={lat['p99']}us "
        f"rulesTotal={row['preflight'].get('rulesTotal', 0)}"
    )
print(f"summary_json={summary_path}")
PY
