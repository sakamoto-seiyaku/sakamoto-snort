#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

MATRIX_MODE="${MATRIX_MODE:-3way}" # 3way|scenario
MATRIX_RUNNER=""

source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

SETTLE_S="${SETTLE_S:-10}"
POLICY0_FREQ="${POLICY0_FREQ:-1328000}"
POLICY4_FREQ="${POLICY4_FREQ:-1328000}"
POLICY6_FREQ="${POLICY6_FREQ:-1426000}"
OUTPUT_DIR=""

usage() {
  cat <<EOF
Usage: $0 [options] -- [neper_udp_perf_matrix options]

This wrapper pins CPU frequencies (best-effort) and then runs neper_udp_perf_matrix.

Fixed-freq options:
  --serial <serial>       Target Android serial
  --adb <path>            adb binary path
  --matrix-mode <mode>    Which matrix runner to invoke: 3way|scenario (default: ${MATRIX_MODE})
  --settle <seconds>      Sleep after pinning freq before running (default: ${SETTLE_S})
  --freq0 <hz>            policy0 fixed freq (default: ${POLICY0_FREQ})
  --freq4 <hz>            policy4 fixed freq (default: ${POLICY4_FREQ})
  --freq6 <hz>            policy6 fixed freq (default: ${POLICY6_FREQ})
  --output-dir <path>     Explicit output directory
  -h, --help              Show help

Example:
  bash $0 --serial 28201JEGR0XPAJ --matrix-mode scenario -- \\
    --rounds-per-scenario 5 --seconds 30 --warmup 10 --cooldown-job 10 \\
    --threads 8 --flows 1024 --bytes 64 --delay-ns 60000 --perfmetrics 0
EOF
}

matrix_args=()
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
    --matrix-mode)
      MATRIX_MODE="$2"
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
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --)
      shift
      matrix_args+=("$@")
      break
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

for v in SETTLE_S POLICY0_FREQ POLICY4_FREQ POLICY6_FREQ; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

case "$MATRIX_MODE" in
  3way) MATRIX_RUNNER="$IPMOD_DIR/neper_udp_perf_matrix.sh" ;;
  scenario) MATRIX_RUNNER="$IPMOD_DIR/neper_udp_perf_scenario_matrix.sh" ;;
  *)
    echo "MATRIX_MODE must be 3way or scenario (got: $MATRIX_MODE)" >&2
    exit 1
    ;;
esac

if [[ -z "${ADB:-}" ]]; then
  ADB="$ADB_BIN"
  export ADB
fi

device_preflight

timestamp_compact_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$IPMOD_DIR/records/neper-udp-perf-fixedfreq-matrix-$(timestamp_compact_utc)_${ADB_SERIAL_RESOLVED}"
fi
mkdir -p "$OUTPUT_DIR"

CONTROLLER_LOG="$OUTPUT_DIR/controller.log"
PLAN_JSON="$OUTPUT_DIR/plan.json"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$CONTROLLER_LOG"
}

capture_device_snapshot() {
  local label="$1"
  local path="$OUTPUT_DIR/${label}.txt"
  adb_su "
echo timestamp=\$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
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

python3 - \
  "$PLAN_JSON" \
  "$ADB_SERIAL_RESOLVED" \
  "$SETTLE_S" \
  "$POLICY0_FREQ" "$POLICY4_FREQ" "$POLICY6_FREQ" \
  "$ORIG_POLICY0_GOV" "$ORIG_POLICY0_MIN" "$ORIG_POLICY0_MAX" \
  "$ORIG_POLICY4_GOV" "$ORIG_POLICY4_MIN" "$ORIG_POLICY4_MAX" \
  "$ORIG_POLICY6_GOV" "$ORIG_POLICY6_MIN" "$ORIG_POLICY6_MAX" \
  -- "${matrix_args[@]}" <<'PY'
import json
import sys
from pathlib import Path

plan_path = Path(sys.argv[1])
adb_serial = sys.argv[2]
settle_s = int(sys.argv[3])

policy0 = int(sys.argv[4])
policy4 = int(sys.argv[5])
policy6 = int(sys.argv[6])

orig_policy0_gov = sys.argv[7]
orig_policy0_min = int(sys.argv[8])
orig_policy0_max = int(sys.argv[9])
orig_policy4_gov = sys.argv[10]
orig_policy4_min = int(sys.argv[11])
orig_policy4_max = int(sys.argv[12])
orig_policy6_gov = sys.argv[13]
orig_policy6_min = int(sys.argv[14])
orig_policy6_max = int(sys.argv[15])

sep_idx = sys.argv.index("--")
matrix_args = sys.argv[sep_idx + 1 :]

payload = {
  "adb_serial": adb_serial,
  "settle_s": settle_s,
  "fixed_freqs": {"policy0": policy0, "policy4": policy4, "policy6": policy6},
  "original": {
    "policy0": {"governor": orig_policy0_gov, "min": orig_policy0_min, "max": orig_policy0_max},
    "policy4": {"governor": orig_policy4_gov, "min": orig_policy4_min, "max": orig_policy4_max},
    "policy6": {"governor": orig_policy6_gov, "min": orig_policy6_min, "max": orig_policy6_max},
  },
  "matrix_args": matrix_args,
}
plan_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
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
  log "cleanup: restore cpu"
  restore_cpu
  capture_device_snapshot "snapshot_restored" || true
}
trap cleanup EXIT

capture_device_snapshot "snapshot_before_pin" || true
log "pin cpu: policy0=$POLICY0_FREQ policy4=$POLICY4_FREQ policy6=$POLICY6_FREQ"
adb_su "
echo performance > /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
printf ${POLICY0_FREQ} > /sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq
printf ${POLICY0_FREQ} > /sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq

echo performance > /sys/devices/system/cpu/cpufreq/policy4/scaling_governor
printf ${POLICY4_FREQ} > /sys/devices/system/cpu/cpufreq/policy4/scaling_min_freq
printf ${POLICY4_FREQ} > /sys/devices/system/cpu/cpufreq/policy4/scaling_max_freq

echo performance > /sys/devices/system/cpu/cpufreq/policy6/scaling_governor
printf ${POLICY6_FREQ} > /sys/devices/system/cpu/cpufreq/policy6/scaling_min_freq
printf ${POLICY6_FREQ} > /sys/devices/system/cpu/cpufreq/policy6/scaling_max_freq
"

capture_device_snapshot "snapshot_after_pin" || true

if [[ "$SETTLE_S" -gt 0 ]]; then
  log "settle: ${SETTLE_S}s"
  sleep "$SETTLE_S"
fi

matrix_output_dir="$OUTPUT_DIR/matrix"
log "run matrix: output_dir=$matrix_output_dir"
bash "$MATRIX_RUNNER" --output-dir "$matrix_output_dir" "${matrix_args[@]}"

log "done: output_dir=$OUTPUT_DIR"
echo "OK output_dir=$OUTPUT_DIR"

