#!/usr/bin/env bash
set -euo pipefail

# Deterministic red/green seam for the throwaway ownership prototype. It does
# not inspect implementation-private runtime counters; it checks the public
# source boundary that the S73 experiment promises to prove.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/../overlay/src/plugins/nfqueue_live_poc"
SOURCE="$PLUGIN_DIR/nfqueue_live_poc.c"
HEADER="$PLUGIN_DIR/nfqueue_live_poc.h"

grep -q '_Static_assert (sizeof (nfqueue_live_meta_t)' "$HEADER"
grep -q 'vlib_buffer_enqueue_to_thread' "$SOURCE"
grep -q 'nfq_set_verdict' "$SOURCE"
grep -q 'vlib_buffer_free_one' "$SOURCE"
grep -q 'NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN' "$SOURCE"
grep -q 'completion_refs' "$SOURCE"
grep -q 'obligation_nonce' "$SOURCE"
grep -q 'nfqueue_live_completion_identity_matches' "$SOURCE"
grep -q 'nfq_get_cap_len' "$SOURCE"
grep -q 'captured_length' "$HEADER"
grep -q 'origin_lane' "$HEADER"
grep -q 'nfqueue_live_enable_dual' "$SOURCE"
grep -q 'NFQUEUE_LIVE_MAX_LANES 4u' "$HEADER"
grep -q 'NF_INET_LOCAL_IN' "$SOURCE"
grep -q 'NF_INET_LOCAL_OUT' "$SOURCE"
grep -q 'live_buffer_receives++' "$SOURCE"
grep -q 'inline_metadata_writes++' "$SOURCE"
grep -q 'payload_pointer_projections++' "$SOURCE"
grep -q 'nfqueue_live_publish_terminal' "$SOURCE"
grep -q 'nfqueue_live_settle_on_origin' "$SOURCE"
grep -q 'nfqueue_live_drain_bounded' "$SOURCE"
grep -q 'origin_return' "$SOURCE"
grep -q 'callback_identities' "$SOURCE"
grep -q 'callback_verdicts' "$SOURCE"
grep -q 'callback_count > 1' "$SOURCE"
grep -q 'ingress_identity_missing' "$SOURCE"
grep -q '!datagram.ingress_identity_missing' "$SOURCE"
grep -q 'stale.reference_held = 0' "$SOURCE"
grep -q '__atomic_load_n (&nm->outstanding' "$SOURCE"
grep -q '__atomic_fetch_add (&nm->outstanding' "$SOURCE"
grep -q '__atomic_fetch_sub (&nm->outstanding' "$SOURCE"
grep -q 'NFQUEUE_LIVE_PACKET_COPY_PATHS 0u' "$SOURCE"
grep -q 'NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS 0u' "$SOURCE"
grep -q 'nfqueue_live_measure_envelope' "$SOURCE"
grep -q 'nfqueue_live_envelope_recover_packet_ids' "$PLUGIN_DIR/nfqueue_live_envelope.h"
grep -q 'nfqueue_live_reject_envelope_messages' "$SOURCE"
grep -q 'NFQUEUE_LIVE_ENVELOPE_MULTI' "$PLUGIN_DIR/nfqueue_live_envelope.h"
grep -q 'envelope_rejected_messages' "$SOURCE"
grep -q 'envelope_recovery_attempts' "$SOURCE"
grep -q 'envelope_recoveries' "$SOURCE"

preflight_line="$(rg -n 'envelope_status = nfqueue_live_measure_envelope' "$SOURCE" | cut -d: -f1)"
handle_line="$(rg -n 'handled = nfq_handle_packet' "$SOURCE" | cut -d: -f1)"
if [ -z "$preflight_line" ] || [ -z "$handle_line" ] ||
   [ "$preflight_line" -ge "$handle_line" ]; then
  echo "netlink envelope preflight must precede nfq_handle_packet" >&2
  exit 1
fi

if rg -n 'verdict_settled' "$PLUGIN_DIR"; then
  echo "datagram-global verdict settlement flag remains in S73 plugin" >&2
  exit 1
fi

for producer in nfqueue_live_owner_node nfqueue_live_ingress_process_node; do
  producer_body="$(awk "/VLIB_NODE_FN \\(${producer}\\)/,/VLIB_REGISTER_NODE/" "$SOURCE")"
  if printf '%s\n' "$producer_body" | rg -n \
      'nfq_set_verdict|vlib_buffer_free_one|nfqueue_live_direct_accept'; then
    echo "producer $producer contains a direct verdict/free operation" >&2
    exit 1
  fi
done
if rg -n 'nfqueue_live_ipv[46]_original_length' "$PLUGIN_DIR"; then
  echo "original length derived from forbidden adapter-local state" >&2
  exit 1
fi

if rg -n '\b(rx_buf|std::vector|malloc|calloc|realloc|memcpy|clib_memcpy)\s*\(' \
  "$PLUGIN_DIR"; then
  echo "forbidden scratch/copy/heap operation found in proven S73 plugin" >&2
  exit 1
fi
if rg -n 'fprintf|printf\s*\(' "$SOURCE"; then
  echo "per-packet synchronous logging found in proven S73 plugin" >&2
  exit 1
fi

echo "S73 static ownership seam: PASS"
echo "inline metadata: $(rg -n '_Static_assert' "$HEADER" | tr '\n' ' ')"
echo "handoff: $(rg -n 'vlib_buffer_enqueue_to_thread' "$SOURCE" | head -1)"
echo "completion: $(rg -n 'nfq_set_verdict \(' "$SOURCE" | tail -1)"
echo "native return: $(rg -n 'vlib_buffer_free_one \(' "$SOURCE" | tail -1)"
