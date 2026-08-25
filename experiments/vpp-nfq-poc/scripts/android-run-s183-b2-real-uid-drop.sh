#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-true}"
export INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"
export INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"
export INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"
export STAGE_PREFIX="${STAGE_PREFIX:-S183}"
export RUNNER_TITLE="${RUNNER_TITLE:-S183 B2 real per-App UID drop}"
export RUNNER_NAME="${RUNNER_NAME:-android-run-s183-b2-real-uid-drop.sh}"
export RUNNER_SCHEMA="${RUNNER_SCHEMA:-s183-b2-real-uid-drop/v1}"
export RUNNER_SCOPE="${RUNNER_SCOPE:-bounded_full_device_b2_real_uid_drop}"
export RUNNER_CLAIM_BOUNDARY="${RUNNER_CLAIM_BOUNDARY:-WSL2-LAN-fixture-real-AppA-UID-drop-at-native-TUN-gate-before-OI3-multi-broker-socket}"
export RUNNER_NON_CLAIM="${RUNNER_NON_CLAIM:-not VPP-internal UID policy, not lifecycle/cache convergence closure, not IPv6, not public internet, not long soak/performance}"
export RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s183-b2-real-uid-drop-$(date +%Y%m%d)}"

exec "$SCRIPT_DIR/android-run-s181-b2-full-device-transport-explore.sh"
