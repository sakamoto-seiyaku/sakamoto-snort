#!/usr/bin/env bash
set -euo pipefail

# S77 source seam: the origin lane is the only physical verdict caller; the
# worker graph carries identity and terminal intent, never policy re-entry or
# packet replacement storage.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/../overlay/src/plugins/nfqueue_live_poc"
SOURCE="$PLUGIN_DIR/nfqueue_live_poc.c"
HEADER="$PLUGIN_DIR/nfqueue_live_poc.h"

grep -q 'NFQUEUE_LIVE_OUTCOME_SUCCEEDED' "$HEADER"
grep -q 'NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE' "$HEADER"
grep -q 'NFQUEUE_LIVE_OUTCOME_UNKNOWN' "$HEADER"
grep -q 'policy_verdict' "$HEADER"
grep -q 'terminal_intent' "$HEADER"
grep -q 'completion_debt' "$HEADER"
grep -q 'completion_duplicate_attempts' "$HEADER"
grep -q 'completion_stale_generation' "$HEADER"
grep -q 'verdict_identity_mismatches' "$HEADER"
grep -q 'inject_verdict_failed_definite' "$HEADER"
grep -q 'inject_verdict_outcome_unknown' "$HEADER"
grep -q 'nfqueue_live_outcome_name' "$SOURCE"
grep -q 'nfqueue_live_record_outcome' "$SOURCE"
grep -q 'nfqueue_live_send_verdict' "$SOURCE"
grep -q 'last_verdict_generation' "$SOURCE"
grep -q 'last_verdict_packet_id' "$SOURCE"
grep -q 'last_verdict_origin_lane' "$SOURCE"
grep -q 'inject-verdict-failed-definite' "$SOURCE"
grep -q 'inject-verdict-outcome-unknown' "$SOURCE"
grep -q 'physical-verdict-attempts' "$SOURCE"
grep -q 'completion-outcome-failed-definite' "$SOURCE"
grep -q 'OUTCOME_UNKNOWN' "$SOURCE"
grep -q 'nfq_set_verdict (lane->queue' "$SOURCE"
grep -q 'completion_debt_raised' "$SOURCE"
grep -q 'completion_debt_settled' "$SOURCE"
grep -q 'retry_attempts' "$SOURCE"
grep -q 'worker_reentries' "$SOURCE"
grep -q 'policy_re_evaluations' "$SOURCE"
grep -q 'replacement_payloads' "$SOURCE"

owner_body="$(awk '/VLIB_NODE_FN \(nfqueue_live_owner_node\)/,/VLIB_REGISTER_NODE/' "$SOURCE")"
ingress_body="$(awk '/VLIB_NODE_FN \(nfqueue_live_ingress_process_node\)/,/VLIB_REGISTER_NODE/' "$SOURCE")"
if printf '%s\n%s\n' "$owner_body" "$ingress_body" | rg -n \
    'nfq_set_verdict|vlib_buffer_free_one|nfqueue_live_direct_accept'; then
  echo "S77 worker/ingress producer contains direct verdict/free" >&2
  exit 1
fi

if rg -n '\b(rx_buf|std::vector|malloc|calloc|realloc|memcpy|clib_memcpy)\s*\(' \
  "$PLUGIN_DIR"; then
  echo "S77 forbidden packet copy/heap operation found" >&2
  exit 1
fi

"$SCRIPT_DIR/test-nfqueue-live-poc-s77-outcome.sh"
echo "S77 static seam: PASS"
