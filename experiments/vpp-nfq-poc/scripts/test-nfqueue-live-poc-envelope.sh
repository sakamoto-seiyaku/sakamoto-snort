#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-74 parser seam. It constructs real netlink/NFQUEUE messages and
# exercises NLMSG/NLA alignment, exact 9000-byte capacity, multi-message
# detection, complete and declared-oversize/MSG_TRUNC rejection, and empty
# payload rejection. Runtime ownership is tested separately by
# run-nfqueue-live-poc.sh; this is not a shell arithmetic substitute.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SOURCE="$POC_DIR/tests/nfqueue_live_envelope_test.c"
BUILD_ROOT="${S74_TEST_BUILD_ROOT:-${TMPDIR:-/tmp}/sakamoto-s74-envelope-test}"
BINARY="$BUILD_ROOT/nfqueue_live_envelope_test"

mkdir -p "$BUILD_ROOT"
cc -std=c11 -Wall -Wextra -Werror -O2 \
  -I"$POC_DIR/overlay/src/plugins/nfqueue_live_poc" \
  -I"$POC_DIR/../../third_party/netfilter/libnetfilter_queue/include" \
  -I"$POC_DIR/../../third_party/netfilter/libnfnetlink/include" \
  "$SOURCE" -o "$BINARY"
"$BINARY"
echo "raw evidence: $SOURCE $BINARY"
