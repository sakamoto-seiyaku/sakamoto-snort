#!/usr/bin/env bash
set -euo pipefail

# S80 source seam: Android remote-owner handoff must not admit NFQUEUE
# obligations until the VPP frame queue can address every worker thread used by
# inline packet metadata.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$SCRIPT_DIR/../overlay/src/plugins/nfqueue_live_poc"
SOURCE="$PLUGIN_DIR/nfqueue_live_poc.c"

grep -q 'nfqueue_live_frame_queue_ready' "$SOURCE"
grep -q 'nfqueue_live_ensure_frame_queue' "$SOURCE"
grep -q 'vec_len (tm->frame_queue_mains)' "$SOURCE"
grep -q 'vec_len (fqm->vlib_frame_queues)' "$SOURCE"
grep -q 'vlib_frame_queue_main_init (nfqueue_live_owner_node.index, 0)' "$SOURCE"

check_enable_body() {
  local name="$1"
  local end_pattern="$2"
  local body
  local ensure_line
  local open_line

  body="$(awk "/^${name} /,/${end_pattern}/" "$SOURCE")"
  printf '%s\n' "$body" | grep -q 'nfqueue_live_ensure_frame_queue'
  printf '%s\n' "$body" | grep -q 'nfqueue_live_open_lane'
  ensure_line="$(printf '%s\n' "$body" | grep -n 'nfqueue_live_ensure_frame_queue' | head -1 | cut -d: -f1)"
  open_line="$(printf '%s\n' "$body" | grep -n 'nfqueue_live_open_lane' | head -1 | cut -d: -f1)"
  if [[ "$ensure_line" -ge "$open_line" ]]; then
    echo "S80 $name opens NFQUEUE lanes before frame queue validation" >&2
    exit 1
  fi
}

check_enable_body 'nfqueue_live_enable' '^nfqueue_live_enable_dual '
check_enable_body 'nfqueue_live_enable_dual' '^nfqueue_live_disable '

for producer in nfqueue_live_owner_node nfqueue_live_ingress_process_node; do
  producer_body="$(awk "/VLIB_NODE_FN \\(${producer}\\)/,/VLIB_REGISTER_NODE/" "$SOURCE")"
  if printf '%s\n' "$producer_body" | rg -n \
      'nfq_set_verdict|vlib_buffer_free_one|nfqueue_live_direct_accept'; then
    echo "S80 producer $producer contains direct verdict/free" >&2
    exit 1
  fi
done

echo "S80 static seam: PASS"
