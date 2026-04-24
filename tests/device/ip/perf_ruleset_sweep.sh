#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

source "$IPMOD_DIR/lib.sh"

DO_DEPLOY=0
SWEEP_SECONDS="${SWEEP_SECONDS:-30}"
LOAD_MODE="${LOAD_MODE:-mix}" # stream|chunk|mix

TRAFFIC_SWEEP_CSV="${TRAFFIC_SWEEP_CSV:-0,10,100,500,1000,2000}"
BG_SWEEP_CSV="${BG_SWEEP_CSV:-0,500,1000,2000}"

BG_UIDS="${BG_UIDS:-200}"

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>        Target Android serial
  --adb <path>             adb binary path
  --deploy                 Deploy sucre-snort daemon first (default: skip)
  --seconds <n>            Duration per point in seconds (default: ${SWEEP_SECONDS})
  --load-mode <mode>       stream|chunk|mix (default: ${LOAD_MODE})
  --traffic <csv>          Traffic-UID rule sweep (default: ${TRAFFIC_SWEEP_CSV})
  --bg <csv>               Background total rule sweep (default: ${BG_SWEEP_CSV})
  --bg-uids <n>            Background UID spread when bg>0 (default: ${BG_UIDS})
  -h, --help               Show help

Notes:
  - This sweep uses Tier-1 (netns+veth) via \`tests/device/ip/cases/60_perf.sh\`.
  - Results are appended to a new records dir under \`tests/device/ip/records/\`.
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
      ADB="${2:?missing adb}"
      export ADB
      shift 2
      ;;
    --deploy)
      DO_DEPLOY=1
      shift
      ;;
    --seconds)
      SWEEP_SECONDS="${2:?missing seconds}"
      shift 2
      ;;
    --load-mode)
      LOAD_MODE="${2:?missing load mode}"
      shift 2
      ;;
    --traffic)
      TRAFFIC_SWEEP_CSV="${2:?missing csv}"
      shift 2
      ;;
    --bg)
      BG_SWEEP_CSV="${2:?missing csv}"
      shift 2
      ;;
    --bg-uids)
      BG_UIDS="${2:?missing bg-uids}"
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

if [[ "$DO_DEPLOY" -eq 1 ]]; then
  bash "$SNORT_ROOT/dev/dev-deploy.sh" >/dev/null
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
serial="${ADB_SERIAL:-unknown}"
out_dir="$IPMOD_DIR/records/perf-ruleset-sweep-${ts}_${serial}"
mkdir -p "$out_dir"

cat >"$out_dir/meta.txt" <<EOF
timestamp=${ts}
serial=${serial}
sweep_seconds=${SWEEP_SECONDS}
load_mode=${LOAD_MODE}
traffic_sweep_csv=${TRAFFIC_SWEEP_CSV}
bg_sweep_csv=${BG_SWEEP_CSV}
bg_uids=${BG_UIDS}
EOF

results_jsonl="$out_dir/results.jsonl"
touch "$results_jsonl"

run_point() {
  local tag="$1"
  local traffic_rules="$2"
  local bg_total="$3"

  local log_path="$out_dir/${tag}.log"
  local proc_before="$out_dir/${tag}_snort_proc_before.txt"
  local proc_after="$out_dir/${tag}_snort_proc_after.txt"
  local proc_delta="$out_dir/${tag}_snort_proc_delta.txt"

  iptest_capture_snort_proc_snapshot >"$proc_before" || true

  set +e
  IPTEST_PERF_LOAD_MODE="$LOAD_MODE" \
    IPTEST_PERF_SECONDS="$SWEEP_SECONDS" \
    IPTEST_PERF_TRAFFIC_RULES="$traffic_rules" \
    IPTEST_PERF_BG_TOTAL="$bg_total" \
    IPTEST_PERF_BG_UIDS="$BG_UIDS" \
    bash "$IPMOD_DIR/cases/60_perf.sh" >"$log_path" 2>&1
  local rc=$?
  set -e

  iptest_capture_snort_proc_snapshot >"$proc_after" || true
  iptest_snort_proc_delta_summary "$proc_before" "$proc_after" >"$proc_delta" || true

  if [[ $rc -ne 0 ]]; then
    echo "FAIL: ${tag} (rc=$rc); see: $log_path" >&2
    return $rc
  fi

  local json_line
  json_line="$(rg -n '^PERF_RESULT_JSON ' "$log_path" | head -n 1 | sed 's/^PERF_RESULT_JSON //')"
  if [[ -z "$json_line" ]]; then
    echo "FAIL: missing PERF_RESULT_JSON in $log_path" >&2
    return 1
  fi

  python3 - "$tag" "$json_line" "$proc_delta" >>"$results_jsonl" <<'PY'
import json
import sys
from pathlib import Path

tag = sys.argv[1]
result = json.loads(sys.argv[2])
delta_path = Path(sys.argv[3])

delta = {}
try:
    for line in delta_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        delta[k.strip()] = v.strip()
except FileNotFoundError:
    pass

result["sweepTag"] = tag
result["snortProcDelta"] = delta
print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY

  echo "OK: ${tag}" >&2
  return 0
}

IFS=',' read -r -a traffic_points <<< "$TRAFFIC_SWEEP_CSV"
IFS=',' read -r -a bg_points <<< "$BG_SWEEP_CSV"

echo "== sweep: traffic UID rules (bg=0) ==" >&2
for n in "${traffic_points[@]}"; do
  [[ -n "$n" ]] || continue
  run_point "traffic_${n}" "$n" 0
done

echo "== sweep: background total rules (traffic=2000) ==" >&2
for n in "${bg_points[@]}"; do
  [[ -n "$n" ]] || continue
  run_point "bg_${n}" 2000 "$n"
done

echo "" >&2
echo "== DONE ==" >&2
echo "records_dir=$out_dir" >&2
echo "results_jsonl=$results_jsonl" >&2
