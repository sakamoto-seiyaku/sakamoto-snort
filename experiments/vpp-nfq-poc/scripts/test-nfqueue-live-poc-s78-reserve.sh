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
  reserve_native_returns reserve_exhaustions reserve_degraded_health \
  reserve_loss_outcome_failed_definite reserve_loss_outcome_unknown \
  reserve_receive_faults inject_receive_fault arm_normal_capacity_exhaustion; do
  rg -q "$symbol" "$HEADER" "$SOURCE"
done

if rg -q 'nfqueue_live_reserve_datagram_t' "$SOURCE"; then
  echo "S78 reserve path retained an unused datagram type" >&2
  exit 1
fi

# The reserve path is deliberately an identity-only direct completion seam. It
# may recover NFQA_PACKET_HDR identity, but cannot call the normal envelope or
# callback parser, enqueue to a worker, allocate a replacement, or issue a
# second Adapter-side verdict.
reserve_body="$(sed -n '/^nfqueue_live_reserve_complete /,/^static void$/p' "$SOURCE")"
if rg -n \
  'nfqueue_live_measure_envelope|nfq_handle_packet|vlib_buffer_enqueue_to_thread|nfqueue_live_direct_accept|vlib_buffer_alloc|memcpy|malloc|calloc|realloc'; then
  echo "S78 reserve path crossed a normal parser/worker/allocation seam" >&2
  exit 1
fi <<<"$reserve_body"
rg -q 'nfqueue_live_recover_packet_id' <<<"$reserve_body"
rg -q 'NFQUEUE_LIVE_ACCEPT' <<<"$reserve_body"
rg -q 'nfqueue_live_reserve_return \(nm, lane, buffer_index, 1\)' <<<"$reserve_body"

startup_body="$(sed -n '/^nfqueue_live_reserve_startup /,/^static void$/p' "$SOURCE")"
rg -q 'nfqueue_live_reserve_release_startup' <<<"$startup_body"
if rg -q 'vlib_buffer_free_one' <<<"$startup_body"; then
  echo "S78 startup path has a second partial-allocation free owner" >&2
  exit 1
fi

loss_body="$(sed -n '/^nfqueue_live_reserve_loss_complete /,/^static nfqueue_live_lane_t /p' "$SOURCE")"
rg -q 'nfqueue_live_record_reserve_loss_outcome' <<<"$loss_body"
rg -q 'nfqueue_live_record_reserve_loss_materialization' <<<"$loss_body"
rg -q 'nfqueue_live_record_reserve_loss_unmaterialized' <<<"$loss_body"
rg -q 'nfqueue_live_record_reserve_loss \(nm, lane\)' <<<"$loss_body"
outcome_body="$(sed -n '/^nfqueue_live_record_reserve_loss_outcome /,/^static nfqueue_live_ingress_result_t$/p' "$SOURCE")"
rg -q 'NFQUEUE_LIVE_OUTCOME_SUCCEEDED' <<<"$outcome_body"
rg -q 'NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE' <<<"$outcome_body"
rg -q 'NFQUEUE_LIVE_OUTCOME_UNKNOWN' <<<"$outcome_body"

receive_body="$(sed -n '/^nfqueue_live_discard_bounded_loss /,/^static_always_inline u8$/p' "$SOURCE")"
rg -q 'reserve_receive_faults' <<<"$receive_body"
rg -q 'NFQUEUE_LIVE_DISCARD_FAULT' <<<"$receive_body"
rg -q 'EAGAIN.*EWOULDBLOCK.*EINTR' <<<"$receive_body"
recv_body="$(sed -n '/^nfqueue_live_netlink_read_ready /,/^static u8$/p' "$SOURCE")"
rg -q 'nfqueue_live_disable_faulted_lane' <<<"$recv_body"
rg -q 'reserve_receive_faults' <<<"$recv_body"
rg -q 'return 0' <<<"$recv_body"
if rg -q 'clib_error_return_unix' <<<"$recv_body"; then
  echo "S78 recv fault path returned an unbounded callback error" >&2
  exit 1
fi
fault_disable_body="$(sed -n '/^nfqueue_live_disable_faulted_lane /,/^static_always_inline u8$/p' "$SOURCE")"
rg -q 'dont_close' <<<"$fault_disable_body"
rg -q 'clib_file_del' <<<"$fault_disable_body"
rg -q 'lane->enabled = 0' <<<"$fault_disable_body"
rg -q 'arm-normal-capacity-exhaustion-after-fill' "$SOURCE"
rg -q 'PROVENANCE_PLUGIN_SHA' "$POC_DIR/scripts/run-nfqueue-live-poc-s78.sh"
rg -q 'COPIED_PLUGIN_SHA' "$POC_DIR/scripts/run-nfqueue-live-poc-s78.sh"
rg -q 'inject-receive-fault' "$SOURCE" "$POC_DIR/scripts/run-nfqueue-live-poc-s78.sh"

# Keep the checked-in host runners parseable alongside the source seam.  This
# catches matrix/scenario edits before a namespace is needed.
bash -n "$SCRIPT_DIR/run-nfqueue-live-poc-s78.sh" \
  "$SCRIPT_DIR/run-nfqueue-live-poc-s78-matrix.sh"

cc -std=c11 -Wall -Wextra -Werror -O2 "$TEST_SOURCE" \
  -o "$BUILD_DIR/nfqueue_live_s78_reserve_test"
"$BUILD_DIR/nfqueue_live_s78_reserve_test"
