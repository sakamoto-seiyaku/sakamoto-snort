#!/usr/bin/env bash
set -euo pipefail

# Deterministic S78 reserve/capacity ledger.  This is a model seam only; the
# real acceptance command is run-nfqueue-live-poc-s78.sh on the VPP/netns path.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_SOURCE="$POC_DIR/tests/nfqueue_live_s78_reserve_test.c"
PLUGIN_DIR="$POC_DIR/overlay/src/plugins/nfqueue_live_poc"
SOURCE="$PLUGIN_DIR/nfqueue_live_poc.c"
HEADER="$PLUGIN_DIR/nfqueue_live_poc.h"
BUILD_DIR="${TMPDIR:-/tmp}/sakamoto-s78-test"
mkdir -p "$BUILD_DIR"

for symbol in \
  NFQUEUE_LIVE_MAX_RESERVE_CAPACITY reserve_indices reserve_startup_reservations \
  reserve_direct_obligations reserve_direct_completions reserve_direct_native_returns \
  reserve_native_returns reserve_exhaustions reserve_degraded_health; do
  rg -q "$symbol" "$HEADER" "$SOURCE"
done

# The reserve path is deliberately an identity-only direct completion seam. It
# may recover NFQA_PACKET_HDR identity, but cannot call the normal envelope or
# callback parser, enqueue to a worker, allocate a replacement, or issue a
# second Adapter-side verdict.
reserve_body="$(sed -n '/^nfqueue_live_reserve_complete /,/^static void$/p' "$SOURCE")"
if printf '%s\n' "$reserve_body" | rg -n \
  'nfqueue_live_measure_envelope|nfq_handle_packet|vlib_buffer_enqueue_to_thread|nfqueue_live_direct_accept|vlib_buffer_alloc|memcpy|malloc|calloc|realloc'; then
  echo "S78 reserve path crossed a normal parser/worker/allocation seam" >&2
  exit 1
fi
printf '%s\n' "$reserve_body" | rg -q 'nfqueue_live_recover_packet_id'
printf '%s\n' "$reserve_body" | rg -q 'NFQUEUE_LIVE_ACCEPT'
printf '%s\n' "$reserve_body" | rg -q 'nfqueue_live_reserve_return \(nm, lane, buffer_index, 1\)'

# Keep the checked-in host runners parseable alongside the source seam.  This
# catches matrix/scenario edits before a namespace is needed.
bash -n "$SCRIPT_DIR/run-nfqueue-live-poc-s78.sh" \
  "$SCRIPT_DIR/run-nfqueue-live-poc-s78-matrix.sh"

cc -std=c11 -Wall -Wextra -Werror -O2 "$TEST_SOURCE" \
  -o "$BUILD_DIR/nfqueue_live_s78_reserve_test"
"$BUILD_DIR/nfqueue_live_s78_reserve_test"
