#!/usr/bin/env bash
set -euo pipefail

# S76 source seam: two-worker placement and bounded completion ledgers are
# checked independently of a runtime namespace.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/../overlay/src/plugins/nfqueue_live_poc"
SOURCE="$PLUGIN_DIR/nfqueue_live_poc.c"
HEADER="$PLUGIN_DIR/nfqueue_live_poc.h"

grep -q '_Static_assert (sizeof (nfqueue_live_meta_t)' "$HEADER"
grep -q 'worker_count' "$HEADER"
grep -q 'initial_worker' "$HEADER"
grep -q 'canonical_worker' "$HEADER"
grep -q 'handoff_stage' "$HEADER"
grep -q 'completion_credit_capacity' "$HEADER"
grep -q 'identity_proof_checks' "$HEADER"
grep -q 'vlib_num_workers' "$SOURCE"
grep -q 'vlib_buffer_enqueue_to_thread' "$SOURCE"
grep -q 'NFQUEUE_LIVE_OWNER_MODE_LOCAL' "$SOURCE"
grep -q 'NFQUEUE_LIVE_OWNER_MODE_REMOTE' "$SOURCE"
grep -q 'NFQUEUE_LIVE_OWNER_MODE_MIXED' "$SOURCE"
grep -q 'nfqueue_live_completion_credit_acquire' "$SOURCE"
grep -q 'nfqueue_live_completion_credit_release' "$SOURCE"
grep -q 'nfqueue_live_record_handoff_before' "$SOURCE"
grep -q 'nfqueue_live_record_handoff_after' "$SOURCE"
grep -q 'NFQUEUE_LIVE_META_CREDIT_BIT' "$SOURCE"
grep -q 'inject-owner-queue-full' "$SOURCE"
grep -q 'inject-completion-credit-exhaustion' "$SOURCE"

for producer in nfqueue_live_owner_node nfqueue_live_ingress_process_node; do
  producer_body="$(awk "/VLIB_NODE_FN \\(${producer}\\)/,/VLIB_REGISTER_NODE/" "$SOURCE")"
  if printf '%s\n' "$producer_body" | rg -n \
      'nfq_set_verdict|vlib_buffer_free_one|nfqueue_live_direct_accept'; then
    echo "S76 producer $producer contains direct verdict/free" >&2
    exit 1
  fi
done
if rg -n '\b(rx_buf|std::vector|malloc|calloc|realloc|memcpy|clib_memcpy)\s*\(' \
  "$PLUGIN_DIR"; then
  echo "S76 forbidden packet copy/heap operation found" >&2
  exit 1
fi

"$SCRIPT_DIR/test-nfqueue-live-poc-s76-ledger.sh"
echo "S76 static seam: PASS"
