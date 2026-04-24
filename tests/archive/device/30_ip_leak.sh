#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$CASE_DIR/../../.." && pwd)"
source "$SNORT_ROOT/tests/archive/device/ip/lib_legacy.sh"

log_section "ip-leak knobs are frozen (fixed/no-op)"

if ! init_test_env; then
  echo "BLOCKED: legacy preflight failed"
  exit 77
fi

iptest_reset_baseline_legacy

assert_frozen_knob "BLOCKIPLEAKS" "1" "0" "BLOCKIPLEAKS frozen/no-op"
assert_frozen_knob "GETBLACKIPS" "1" "0" "GETBLACKIPS frozen/no-op"
assert_frozen_knob "MAXAGEIP" "1" "14400" "MAXAGEIP frozen/no-op"

expect_ok "RESETALL" "RESETALL (frozen knobs remain fixed)"

bil="$(send_cmd "BLOCKIPLEAKS")"
if [[ "$bil" == "0" ]]; then
  log_pass "BLOCKIPLEAKS remains 0 after RESETALL"
else
  log_fail "BLOCKIPLEAKS changed after RESETALL"
  exit 4
fi

gbi="$(send_cmd "GETBLACKIPS")"
if [[ "$gbi" == "0" ]]; then
  log_pass "GETBLACKIPS remains 0 after RESETALL"
else
  log_fail "GETBLACKIPS changed after RESETALL"
  exit 4
fi

mai="$(send_cmd "MAXAGEIP")"
if [[ "$mai" == "14400" ]]; then
  log_pass "MAXAGEIP remains 14400 after RESETALL"
else
  log_fail "MAXAGEIP changed after RESETALL"
  exit 4
fi

log_pass "legacy frozen knobs ok"
exit 0
