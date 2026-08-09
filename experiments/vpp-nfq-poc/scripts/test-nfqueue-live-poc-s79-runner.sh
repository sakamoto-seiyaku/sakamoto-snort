#!/usr/bin/env bash
set -euo pipefail

# Source/runner gate for S79.  The live matrix requires a disposable root
# network namespace; this gate remains runnable on an ordinary host and
# catches drift in every scenario before attempting that environment.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$SCRIPT_DIR/run-nfqueue-live-poc-s79.sh"
MATRIX="$SCRIPT_DIR/run-nfqueue-live-poc-s79-matrix.sh"
SOURCE="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.c"
HEADER="$POC_DIR/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_teardown.h"
TEST_SOURCE="$POC_DIR/tests/nfqueue_live_s79_teardown_test.c"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/s79-runner.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

bash -n "$RUNNER" "$MATRIX"
rg -q 'queue-disable' "$RUNNER" "$MATRIX"
rg -q 'clean-stop' "$RUNNER" "$MATRIX"
rg -q 'drain-deadline' "$RUNNER" "$MATRIX"
rg -q 'process-termination' "$RUNNER" "$MATRIX"
rg -q 'fresh-restart' "$RUNNER" "$MATRIX"
rg -q 'multiple-generations' "$RUNNER" "$MATRIX"
rg -q 'disable_runtime deadline' "$RUNNER"
rg -q 'kill -KILL' "$RUNNER"
rg -q 'teardown-transition' "$RUNNER" "$SOURCE"
rg -q 'teardown-obligation-residue' "$RUNNER" "$SOURCE"
rg -q 'completion-debt' "$RUNNER" "$SOURCE"
rg -q 'completion-credits-held' "$RUNNER" "$SOURCE"
rg -q 'teardown-resources' "$RUNNER" "$SOURCE"
rg -q 'netlink-fd' "$RUNNER" "$SOURCE"
rg -q 'queue-open' "$RUNNER" "$SOURCE"
rg -q 'queue_rule_present' "$RUNNER"
rg -q 'NFQUEUE_LIVE_TEARDOWN_PROCESS_DEATH' "$HEADER"

cc -std=c11 -Wall -Wextra -Werror -O2 "$TEST_SOURCE" \
  -o "$BUILD_DIR/nfqueue_live_s79_teardown_test"
"$BUILD_DIR/nfqueue_live_s79_teardown_test"

echo "S79 runner/static gate: PASS"
