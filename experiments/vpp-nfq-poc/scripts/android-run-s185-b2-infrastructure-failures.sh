#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export INCLUDE_INFRA_FAILURES="${INCLUDE_INFRA_FAILURES:-true}"
export INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"
export INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-false}"
export INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-false}"
export INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-false}"
export STAGE_PREFIX="${STAGE_PREFIX:-S185}"
export RUNNER_TITLE="${RUNNER_TITLE:-S185 B2 bind/protect/broker infrastructure failure separation}"
export RUNNER_NAME="${RUNNER_NAME:-android-run-s185-b2-infrastructure-failures.sh}"
export RUNNER_SCHEMA="${RUNNER_SCHEMA:-s185-b2-infrastructure-failures/v1}"
export RUNNER_SCOPE="${RUNNER_SCOPE:-bounded_full_device_b2_infrastructure_failure_separation}"
export RUNNER_CLAIM_BOUNDARY="${RUNNER_CLAIM_BOUNDARY:-WSL2-LAN-fixture-real-AppA-positive-control-plus-bind-protect-broker-failure-before-OI3-connector-transport}"
export RUNNER_NON_CLAIM="${RUNNER_NON_CLAIM:-not-policy-drop, not-post-connect-transport-failure, not-public-internet, not-production-capacity-or-timeout-constants}"
export RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s185-b2-infrastructure-failures-$(date +%Y%m%d)}"

exec "$SCRIPT_DIR/android-run-s181-b2-full-device-transport-explore.sh"
