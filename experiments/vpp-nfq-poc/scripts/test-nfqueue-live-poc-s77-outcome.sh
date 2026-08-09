#!/usr/bin/env bash
set -euo pipefail

# Deterministic S77 evidence for tri-state completion and immutable policy
# intent.  The live runner supplies the VPP/native round trip; this model
# keeps stale, duplicate, definite-failure, and unknown outcomes reproducible
# without a network namespace.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/../tests" && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/s77-outcome.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$TEST_DIR/nfqueue_live_s77_outcome_test.c" \
  -o "$BUILD_DIR/nfqueue_live_s77_outcome_test"
"$BUILD_DIR/nfqueue_live_s77_outcome_test"
