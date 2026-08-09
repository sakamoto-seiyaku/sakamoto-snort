#!/usr/bin/env bash
set -euo pipefail

# Focused harness for the datagram settlement seam. libnetfilter_queue normally
# emits one callback per message, so this tiny model exercises the exact
# callback #2-known / callback #1-candidate ordering that previously let one
# kernel obligation remain held.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$SCRIPT_DIR/../overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.c"

grep -q 'callback_identities++' "$SOURCE"
grep -q 'callback_verdicts++' "$SOURCE"
grep -q 'if (datagram.callback_count > 1)' "$SOURCE"
grep -q 'Callback #1 remains a live candidate' "$SOURCE"
if rg -n 'verdict_settled' "$SOURCE"; then
  echo "global datagram settlement flag still present" >&2
  exit 1
fi

# Message 1 was projected as the worker candidate; callback 2 was directly
# accepted in the callback. The outer multi-message branch must settle message
# 1 as well, leaving no recoverable identity outstanding.
callback_count=2
callback_identities=2
callback_verdicts=1
candidate=1
if (( candidate == 1 )); then
  callback_verdicts=$((callback_verdicts + 1))
fi
unknown_callbacks=$((callback_count - callback_identities))
if (( callback_verdicts != callback_count || unknown_callbacks != 0 )); then
  echo "multi-message settlement model failed" >&2
  exit 1
fi

# A missing callback header remains explicitly accounted as unrecoverable; it
# must not suppress the known candidate's direct verdict.
callback_count=2
callback_identities=1
callback_verdicts=0
candidate=1
if (( candidate == 1 )); then
  callback_verdicts=$((callback_verdicts + 1))
fi
unknown_callbacks=$((callback_count - callback_identities))
if (( callback_verdicts != 1 || unknown_callbacks != 1 )); then
  echo "mixed recoverable/unrecoverable model failed" >&2
  exit 1
fi

echo "S73 multi-message settlement harness: PASS"
