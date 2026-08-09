#!/usr/bin/env bash
set -euo pipefail

# S79 source seam: the live plugin and deterministic model must share the
# strict quiesce -> drain -> close-completion -> close-channels order.  This
# is intentionally source-only and has no VPP/network namespace dependency.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HEADER="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_teardown.h"
PLUGIN="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.c"

rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_QUIESCING' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_DRAINING' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION' "$HEADER"
rtk rg -q 'NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS' "$HEADER"
rtk rg -q 'nfqueue_live_teardown_generation_allowed' "$HEADER"
rtk rg -q 'quiescing' "$PLUGIN"
rtk rg -q 'nfqueue_live_drain_bounded' "$PLUGIN"
rtk rg -q 'nfqueue_live_close_completion' "$PLUGIN" || true

echo "S79 teardown static state seam: PASS"
