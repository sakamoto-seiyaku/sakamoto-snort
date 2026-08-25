#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-true}"
export INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"
export INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"
export STAGE_PREFIX="${STAGE_PREFIX:-S182}"
export RUNNER_TITLE="${RUNNER_TITLE:-S182 B2 real target-IP policy drop}"
export RUNNER_NAME="${RUNNER_NAME:-android-run-s182-b2-real-policy-drop.sh}"
export RUNNER_SCHEMA="${RUNNER_SCHEMA:-s182-b2-real-policy-drop/v1}"
export RUNNER_SCOPE="${RUNNER_SCOPE:-bounded_full_device_b2_real_policy_drop}"
export RUNNER_CLAIM_BOUNDARY="${RUNNER_CLAIM_BOUNDARY:-WSL2-LAN-fixture-real-target-IP-policy-drop-before-OI3-multi-owner-admission}"
export RUNNER_NON_CLAIM="${RUNNER_NON_CLAIM:-not per-App UID drop, not IPv6, not public internet, not long soak/performance}"
export RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s182-b2-real-policy-drop-$(date +%Y%m%d)}"

exec "$SCRIPT_DIR/android-run-s181-b2-full-device-transport-explore.sh"
