#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify RuntimeService supervisor cleanup after daemon SIGKILL.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_ID=22-sigkill-supervisor EXPECT_AUTOMATIC_SIGKILL_CLEANUP=1 \
  exec bash "$SCRIPT_DIR/android-run-daemon-signal-boundary-poc.sh" "$@"
