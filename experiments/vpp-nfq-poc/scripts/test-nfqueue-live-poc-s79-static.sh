#!/usr/bin/env bash
set -euo pipefail

# S79 source seam: the live plugin and deterministic model must share the
# strict quiesce -> drain -> close-completion -> close-channels order.  This
# is intentionally source-only and has no VPP/network namespace dependency.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HEADER="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_teardown.h"
PLUGIN="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.c"
MAIN_HEADER="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.h"

rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_QUIESCING' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_DRAINING' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS' "$HEADER"
rtk rg -q 'nfqueue_live_teardown_generation_allowed' "$HEADER"
rtk rg -q 'nfqueue_live_teardown_completion_generation_allowed' "$HEADER"
rtk rg -q 'nfqueue_live_teardown_completion_channel_open' "$HEADER"
rtk rg -q 'nfqueue_live_teardown.h' "$MAIN_HEADER"
rtk rg -q 'nfqueue_live_record_teardown_transition' "$PLUGIN"
rtk rg -q 'teardown-transition' "$PLUGIN"
rtk rg -q 'teardown-deadline-accepts' "$PLUGIN"
rtk rg -q 'teardown-obligation-residue' "$PLUGIN"
rtk rg -q 'nfqueue_live_teardown_ingress_allowed' "$PLUGIN"
rtk rg -q 'nfqueue_live_drain_bounded' "$PLUGIN"
rtk rg -q 'nfqueue_live_close_completion_channel' "$PLUGIN"
rtk rg -q 'nfqueue_live_publish_late_return' "$PLUGIN"
rtk rg -q 'nfqueue_live_drain_late_return_queue' "$PLUGIN"
rtk rg -q 'late_return' "$PLUGIN" "$MAIN_HEADER"
rtk rg -q 'nfqueue_live_state \\(meta\\) != NFQUEUE_LIVE_STATE_RETURNED' "$PLUGIN"
rtk rg -q 'hold_obligation' "$PLUGIN" "$MAIN_HEADER"
rtk rg -q 'hold-obligation' "$PLUGIN"
rtk rg -q 'teardown-late-settlements' "$PLUGIN"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION' "$PLUGIN"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS' "$PLUGIN"
rtk rg -q 'teardown_deadline_forced' "$PLUGIN"

echo "S79 teardown static state seam: PASS"
