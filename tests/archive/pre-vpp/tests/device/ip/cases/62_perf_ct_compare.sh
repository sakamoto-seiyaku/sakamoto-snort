#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "conntrack perf compare (tier1)"

if [[ "${IPTEST_PERF_CT_COMPARE:-0}" != "1" ]]; then
  echo "SKIP: set IPTEST_PERF_CT_COMPARE=1 to run the ct perf compare (runs 60_perf.sh twice)"
  exit 10
fi

log_info "scenario A: ct=off (no ct consumers => conntrack update skipped)"
IPTEST_PERF_ENABLE_CT=0 bash "$CASE_DIR/60_perf.sh"

log_info "scenario B: ct=on (ct consumer rule installed => conntrack update on hot path)"
IPTEST_PERF_ENABLE_CT=1 bash "$CASE_DIR/60_perf.sh"

log_pass "conntrack perf compare done"
exit 0

