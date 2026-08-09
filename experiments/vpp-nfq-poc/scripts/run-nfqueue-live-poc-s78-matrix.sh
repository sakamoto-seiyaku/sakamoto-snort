#!/usr/bin/env bash
set -euo pipefail

# S78 host matrix. Run this script inside the disposable user/network
# namespace used by the other POC runners, for example:
#   rtk unshare -Urn ./scripts/run-nfqueue-live-poc-s78-matrix.sh
# Each case starts a fresh VPP process and owns a distinct netlink topology;
# no case shares reserve state with another.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MATRIX_DIR="${S78_MATRIX_DIR:-/tmp/sakamoto-s78-matrix}"
mkdir -p "$MATRIX_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "S78 matrix needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
  exit 1
fi

run_case() {
  local name="$1" fault="$2" queue="$3" host_if="$4" peer_if="$5"
  local evidence="$MATRIX_DIR/$name"
  local runtime="/tmp/sakamoto-vpp-nfqueue-s78-$name"
  local netns="/tmp/sakamoto-nfqueue-s78-state-$name"
  echo "S78 matrix case=$name fault=$fault evidence=$evidence"
  S78_FAULT="$fault" \
    S78_QUEUE_BASE="$queue" \
    S78_HOST_IF="$host_if" \
    S78_PEER_IF="$peer_if" \
    S78_RUNTIME_ROOT="$runtime" \
    S78_NETNS_STATE="$netns" \
    S78_EVIDENCE_DIR="$evidence" \
    S78_REGULAR_MEMFD="${S78_REGULAR_MEMFD:-1}" \
    "$SCRIPT_DIR/run-nfqueue-live-poc-s78.sh"
}

run_case reserve_direct reserve-direct 42 nfq78d-h nfq78d-p
run_case reserve_exhaustion reserve-exhaustion 52 nfq78e-h nfq78e-p
run_case reserve_stress reserve-stress 62 nfq78s-h nfq78s-p

echo "S78 runtime matrix: PASS"
echo "evidence root: $MATRIX_DIR"
