#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_RUNNER="$SCRIPT_DIR/run_kernel_panic_sock_ioctl_host.sh"

if [[ ! -f "$HOST_RUNNER" ]]; then
  echo "FATAL: host runner missing: $HOST_RUNNER" >&2
  exit 1
fi

BASE_RUN_ID="${RUN_ID_PREFIX:-$(date -u +%Y%m%dT%H%M%SZ)}"
PER_CASE_SECONDS="${IPTEST_PERF_SECONDS:-60}"
PER_CASE_ITERS="${LOAD_MAX_ITERS:-1}"

run_case() {
  local case_id="$1"
  local server_mode="$2"
  local load_mode="$3"
  local load_wrapper="$4"

  echo ""
  echo "== case=$case_id server_mode=$server_mode load_mode=$load_mode load_wrapper=$load_wrapper =="

  RUN_ID="${BASE_RUN_ID}_${case_id}" \
  REPRO_MODE=net_only \
  STOP_SNORT=1 \
  SERVER_MODE="$server_mode" \
  LOAD_MODE="$load_mode" \
  LOAD_WRAPPER="$load_wrapper" \
  IPTEST_PERF_SECONDS="$PER_CASE_SECONDS" \
  LOAD_MAX_ITERS="$PER_CASE_ITERS" \
    bash "$HOST_RUNNER"
}

run_case "01_sh_connect_q0" "sh_cat_zero" "connect_q0" "su_sh"
run_case "02_sh_head1" "sh_cat_zero" "head1_only" "su_sh"
run_case "03_cat_connect_q0" "cat_zero" "connect_q0" "su_sh"
run_case "04_cat_head1" "cat_zero" "head1_only" "su_sh"
