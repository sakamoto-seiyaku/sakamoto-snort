#!/usr/bin/env bash
set -euo pipefail

# Deterministic S76 evidence: the bounded worker/credit/identity model runs
# without CAP_NET_ADMIN or a live VPP process.  Runtime conformance is covered
# by run-nfqueue-live-poc-s76.sh; this test makes fault closure reproducible.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/../tests" && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/s76-ledger.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$TEST_DIR/nfqueue_live_s76_ledger_test.c" \
  -o "$BUILD_DIR/nfqueue_live_s76_ledger_test"
"$BUILD_DIR/nfqueue_live_s76_ledger_test"
