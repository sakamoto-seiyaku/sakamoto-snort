#!/bin/bash

set -euo pipefail

ARCHIVE_IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$ARCHIVE_IPMOD_DIR/../../../.." && pwd)"

# Legacy text-protocol helpers live under tests/archive.
source "$SNORT_ROOT/tests/archive/integration/lib_legacy.sh"

# Reuse vNext-only Tier-1 helpers (netns/veth/load generators, etc.).
#
# NOTE: sourcing this will temporarily overwrite IPMOD_DIR; restore it after load
# so archive scripts can keep using their own $IPMOD_DIR for relative paths.
source "$SNORT_ROOT/tests/device/ip/lib.sh"
IPMOD_DIR="$ARCHIVE_IPMOD_DIR"

# -----------------------------------------------------------------------------
# Legacy expectations (archive-only)
# -----------------------------------------------------------------------------

expect_ok() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc"
    echo "    cmd: $cmd"
    echo "    got: $result"
    return 1
  fi

  if [[ "$result" == "OK" ]]; then
    log_pass "$desc"
    return 0
  fi

  log_fail "$desc"
  echo "    cmd: $cmd"
  echo "    got: $result"
  return 1
}

expect_nok() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc"
    echo "    cmd: $cmd"
    echo "    got: $result"
    return 1
  fi

  if [[ "$result" == "NOK" ]]; then
    log_pass "$desc"
    return 0
  fi

  log_fail "$desc"
  echo "    cmd: $cmd"
  echo "    got: $result"
  return 1
}

expect_uint() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc" >&2
    echo "    cmd: $cmd" >&2
    echo "    got: $result" >&2
    return 1
  fi

  if [[ "$result" =~ ^[0-9]+$ ]]; then
    log_pass "$desc (value=$result)" >&2
    echo "$result"
    return 0
  fi

  log_fail "$desc" >&2
  echo "    cmd: $cmd" >&2
  echo "    got: $result" >&2
  return 1
}

iptest_reset_baseline_legacy() {
  assert_ok "RESETALL" "RESETALL baseline"
  assert_ok "BLOCK 1" "BLOCK=1"
  assert_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS=0"
  assert_ok "IPRULES 1" "IPRULES=1"
  assert_ok "BLOCKIFACE ${IPTEST_UID} 0" "BLOCKIFACE cleared for uid=$IPTEST_UID"
}

