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
grep -q 'live_buffer_receives++' "$SOURCE"
grep -q 'inline_metadata_writes++' "$SOURCE"
grep -q 'payload_pointer_projections++' "$SOURCE"
grep -q 'nfqueue_live_settle_fail_open' "$SOURCE"
grep -q 'nfqueue_live_drain_bounded' "$SOURCE"
grep -q 'NFQUEUE_LIVE_PACKET_COPY_PATHS 0u' "$SOURCE"
grep -q 'NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS 0u' "$SOURCE"
if rg -n 'nfqueue_live_ipv[46]_original_length|meta->(captured_length|origin_lane)' \
  "$PLUGIN_DIR"; then
  echo "original length or lane identity derived from forbidden adapter-local state" >&2
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
