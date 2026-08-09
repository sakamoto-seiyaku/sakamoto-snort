#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-79 scenario matrix.  Every case has a separate namespace, VPP
# runtime, queue range, and evidence directory; process-death residue is
# therefore classified independently before supervisor cleanup.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MATRIX_DIR="${S79_MATRIX_DIR:-/tmp/sakamoto-s79-matrix}"
mkdir -p "$MATRIX_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "S79 matrix needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
  exit 1
fi

run_case() {
  local name="$1" queue="$2"
  local evidence="$MATRIX_DIR/$name"
  local runtime="/tmp/sakamoto-vpp-nfqueue-s79-$name"
  local netns="/tmp/sakamoto-nfqueue-s79-state-$name"
  echo "S79 matrix case=$name evidence=$evidence"
  S79_CASE="$name" \
    S79_QUEUE_BASE="$queue" \
    S79_RUNTIME_ROOT="$runtime" \
    S79_NETNS_STATE="$netns" \
    S79_EVIDENCE_DIR="$evidence" \
    "$SCRIPT_DIR/run-nfqueue-live-poc-s79.sh"
}

run_case queue-disable 42
run_case clean-stop 52
run_case drain-deadline 62
run_case process-termination 72
run_case fresh-restart 82
S79_ROUNDS="${S79_ROUNDS:-3}" run_case multiple-generations 92

echo "S79 runtime matrix: PASS"
echo "evidence root: $MATRIX_DIR"
