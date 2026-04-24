#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"
RUNNER="$IPMOD_DIR/run.sh"

PERF_SECONDS="${PERF_SECONDS:-300}"
PERF_LOAD_MODE="${PERF_LOAD_MODE:-stream}"
HEAVY_TRAFFIC_RULES="${HEAVY_TRAFFIC_RULES:-2000}"
HEAVY_BG_TOTAL="${HEAVY_BG_TOTAL:-2000}"
HEAVY_BG_UIDS="${HEAVY_BG_UIDS:-200}"
DO_DEPLOY=0
SCENARIO_ORDER="${SCENARIO_ORDER:-iprules_off_empty,iprules_on_empty,iprules_on_heavy}"

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>        Target device serial
  --seconds <n>            Duration per scenario in seconds (default: ${PERF_SECONDS})
  --deploy                 Run deploy before each test batch (default: skip deploy)
  --rules <n>              Heavy traffic-uid rule count (default: ${HEAVY_TRAFFIC_RULES})
  --bg-total <n>           Heavy background rule count (default: ${HEAVY_BG_TOTAL})
  --bg-uids <n>            Heavy background UID spread (default: ${HEAVY_BG_UIDS})
  --order <csv>            Scenario order (default: ${SCENARIO_ORDER})
  -h, --help               Show help

Scenarios:
  1. iprules_off_empty     IPRULES=0, empty ruleset
  2. iprules_on_empty      IPRULES=1, empty ruleset
  3. iprules_on_heavy      IPRULES=1, heavy ruleset
EOF
}

ADB_SERIAL_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="${2:?missing serial}"
      export ADB_SERIAL
      ADB_SERIAL_ARG="--serial $ADB_SERIAL"
      shift 2
      ;;
    --seconds)
      PERF_SECONDS="${2:?missing seconds}"
      shift 2
      ;;
    --deploy)
      DO_DEPLOY=1
      shift
      ;;
    --rules)
      HEAVY_TRAFFIC_RULES="${2:?missing rules}"
      shift 2
      ;;
    --bg-total)
      HEAVY_BG_TOTAL="${2:?missing bg-total}"
      shift 2
      ;;
    --bg-uids)
      HEAVY_BG_UIDS="${2:?missing bg-uids}"
      shift 2
      ;;
    --order)
      SCENARIO_ORDER="${2:?missing order}"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

if [[ ! "$PERF_SECONDS" =~ ^[0-9]+$ || "$PERF_SECONDS" -le 0 ]]; then
  echo "PERF_SECONDS must be a positive integer (got: $PERF_SECONDS)" >&2
  exit 1
fi

if [[ ! "$HEAVY_TRAFFIC_RULES" =~ ^[0-9]+$ || ! "$HEAVY_BG_TOTAL" =~ ^[0-9]+$ || ! "$HEAVY_BG_UIDS" =~ ^[0-9]+$ ]]; then
  echo "heavy rules/bg arguments must be non-negative integers" >&2
  exit 1
fi

declare -A SCENARIO_IPRULES=(
  [iprules_off_empty]=0
  [iprules_on_empty]=1
  [iprules_on_heavy]=1
)
declare -A SCENARIO_TRAFFIC_RULES=(
  [iprules_off_empty]=0
  [iprules_on_empty]=0
  [iprules_on_heavy]="$HEAVY_TRAFFIC_RULES"
)
declare -A SCENARIO_BG_TOTAL=(
  [iprules_off_empty]=0
  [iprules_on_empty]=0
  [iprules_on_heavy]="$HEAVY_BG_TOTAL"
)
declare -A SCENARIO_BG_UIDS=(
  [iprules_off_empty]=0
  [iprules_on_empty]=0
  [iprules_on_heavy]="$HEAVY_BG_UIDS"
)

IFS=',' read -r -a SCENARIOS <<< "$SCENARIO_ORDER"
if [[ "${#SCENARIOS[@]}" -ne 3 ]]; then
  echo "SCENARIO_ORDER must list exactly 3 comma-separated scenarios" >&2
  exit 1
fi
declare -A seen=()
for scenario in "${SCENARIOS[@]}"; do
  if [[ -z "${SCENARIO_IPRULES[$scenario]+x}" ]]; then
    echo "unknown scenario in order: $scenario" >&2
    exit 1
  fi
  if [[ -n "${seen[$scenario]:-}" ]]; then
    echo "duplicate scenario in order: $scenario" >&2
    exit 1
  fi
  seen[$scenario]=1
done

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ipperf3way.XXXXXX")"
RESULTS_JSONL="$LOG_DIR/results.jsonl"

run_scenario() {
  local name="$1"
  local single_iprules="$2"
  local traffic_rules="$3"
  local bg_total="$4"
  local bg_uids="$5"
  local log_file="$LOG_DIR/${name}.log"

  local -a cmd=(
    env
    "IPTEST_PERF_SECONDS=$PERF_SECONDS"
    "IPTEST_PERF_LOAD_MODE=$PERF_LOAD_MODE"
    "IPTEST_PERF_COMPARE=0"
    "IPTEST_PERF_SINGLE_IPRULES=$single_iprules"
    "IPTEST_PERF_TRAFFIC_RULES=$traffic_rules"
    "IPTEST_PERF_BG_TOTAL=$bg_total"
    "IPTEST_PERF_BG_UIDS=$bg_uids"
    bash "$RUNNER"
    --profile perf
  )

  if [[ $DO_DEPLOY -eq 0 ]]; then
    cmd+=(--skip-deploy)
  fi
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    cmd+=(--serial "$ADB_SERIAL")
  fi

  echo ""
  echo "=== PERF SCENARIO: $name ==="
  echo "seconds=$PERF_SECONDS load_mode=$PERF_LOAD_MODE iprules=$single_iprules traffic_rules=$traffic_rules bg_total=$bg_total bg_uids=$bg_uids"

  "${cmd[@]}" | tee "$log_file"

  local result_line
  result_line="$(grep 'PERF_RESULT_JSON ' "$log_file" | tail -n 1 || true)"
  if [[ -z "$result_line" ]]; then
    echo "missing PERF_RESULT_JSON in $log_file" >&2
    exit 1
  fi

  result_line="${result_line#PERF_RESULT_JSON }"
  printf '%s\n' "$result_line" >> "$RESULTS_JSONL"
}

for scenario in "${SCENARIOS[@]}"; do
  run_scenario \
    "$scenario" \
    "${SCENARIO_IPRULES[$scenario]}" \
    "${SCENARIO_TRAFFIC_RULES[$scenario]}" \
    "${SCENARIO_BG_TOTAL[$scenario]}" \
    "${SCENARIO_BG_UIDS[$scenario]}"
done

SUMMARY_JSON="$LOG_DIR/summary.json"

python3 - "$RESULTS_JSONL" "$PERF_SECONDS" "$SUMMARY_JSON" "$SCENARIO_ORDER" <<'PY'
import json
import sys
from pathlib import Path

results_path = Path(sys.argv[1])
seconds = int(sys.argv[2])
summary_path = Path(sys.argv[3])
scenario_order = [name for name in sys.argv[4].split(",") if name]

rows = [json.loads(line) for line in results_path.read_text().splitlines() if line.strip()]
if len(rows) != len(scenario_order):
    raise SystemExit(f"expected {len(scenario_order)} result rows, got {len(rows)}")

for scenario_name, row in zip(scenario_order, rows):
    row["scenario"] = scenario_name
    row["rate_mib_s"] = row["bytes"] / seconds / 1024 / 1024
    row["rate_gib_s"] = row["bytes"] / seconds / 1024 / 1024 / 1024

def delta(current, base):
    if base == 0:
        return None
    return (current - base) / base * 100.0

by_scenario = {row["scenario"]: row for row in rows}
off = by_scenario["iprules_off_empty"]
on_empty = by_scenario["iprules_on_empty"]
on_heavy = by_scenario["iprules_on_heavy"]
summary = {
    "seconds": seconds,
    "scenario_order": scenario_order,
    "scenarios": rows,
    "deltas_pct": {
        "empty_on_vs_off": {
            "bytes": delta(on_empty["bytes"], off["bytes"]),
            "connections": delta(on_empty.get("connections", 0), off.get("connections", 0)),
            "samples": delta(on_empty["samples"], off["samples"]),
            "avg": delta(on_empty["latency_us"]["avg"], off["latency_us"]["avg"]),
            "p50": delta(on_empty["latency_us"]["p50"], off["latency_us"]["p50"]),
            "p95": delta(on_empty["latency_us"]["p95"], off["latency_us"]["p95"]),
            "p99": delta(on_empty["latency_us"]["p99"], off["latency_us"]["p99"]),
            "max": delta(on_empty["latency_us"]["max"], off["latency_us"]["max"]),
        },
        "heavy_vs_empty_on": {
            "bytes": delta(on_heavy["bytes"], on_empty["bytes"]),
            "connections": delta(on_heavy.get("connections", 0), on_empty.get("connections", 0)),
            "samples": delta(on_heavy["samples"], on_empty["samples"]),
            "avg": delta(on_heavy["latency_us"]["avg"], on_empty["latency_us"]["avg"]),
            "p50": delta(on_heavy["latency_us"]["p50"], on_empty["latency_us"]["p50"]),
            "p95": delta(on_heavy["latency_us"]["p95"], on_empty["latency_us"]["p95"]),
            "p99": delta(on_heavy["latency_us"]["p99"], on_empty["latency_us"]["p99"]),
            "max": delta(on_heavy["latency_us"]["max"], on_empty["latency_us"]["max"]),
        },
        "heavy_vs_off": {
            "bytes": delta(on_heavy["bytes"], off["bytes"]),
            "connections": delta(on_heavy.get("connections", 0), off.get("connections", 0)),
            "samples": delta(on_heavy["samples"], off["samples"]),
            "avg": delta(on_heavy["latency_us"]["avg"], off["latency_us"]["avg"]),
            "p50": delta(on_heavy["latency_us"]["p50"], off["latency_us"]["p50"]),
            "p95": delta(on_heavy["latency_us"]["p95"], off["latency_us"]["p95"]),
            "p99": delta(on_heavy["latency_us"]["p99"], off["latency_us"]["p99"]),
            "max": delta(on_heavy["latency_us"]["max"], off["latency_us"]["max"]),
        },
    },
}

summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

print("")
print("=== PERF 3-WAY SUMMARY ===")
for row in rows:
    lat = row["latency_us"]
    pre = row["preflight"]
    print(
        f"{row['scenario']}: "
        f"rate={row['rate_mib_s']:.2f} MiB/s "
        f"bytes={row['bytes']} "
        f"connections={row.get('connections', 0)} "
        f"samples={row['samples']} "
        f"lat(us) min={lat['min']} avg={lat['avg']} p50={lat['p50']} "
        f"p95={lat['p95']} p99={lat['p99']} max={lat['max']} "
        f"rulesTotal={pre.get('rulesTotal', 0)} subtablesTotal={pre.get('subtablesTotal', 0)}"
    )

def print_delta(name, data):
    parts = []
    for key in ("bytes", "connections", "samples", "avg", "p50", "p95", "p99", "max"):
        value = data[key]
        if value is None:
            parts.append(f"{key}=n/a")
        else:
            parts.append(f"{key}={value:+.2f}%")
    print(f"{name}: " + " ".join(parts))

print("")
print_delta("delta empty_on_vs_off", summary["deltas_pct"]["empty_on_vs_off"])
print_delta("delta heavy_vs_empty_on", summary["deltas_pct"]["heavy_vs_empty_on"])
print_delta("delta heavy_vs_off", summary["deltas_pct"]["heavy_vs_off"])
print("")
print("PERF_3WAY_SUMMARY_JSON " + json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
print(f"logs={results_path.parent}")
print(f"summary_json={summary_path}")
PY
