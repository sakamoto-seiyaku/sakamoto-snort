#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: measure abnormal daemon exit and the bounded restart boundary.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_ID=23-daemon-crash-restart \
CRASH_SIGNAL=ABRT \
CRASH_LABEL=SIGABRT \
EXPECT_AUTOMATIC_CRASH_CLEANUP=1 \
EXPECT_NO_AUTOMATIC_RESTART=1 \
  exec bash "$SCRIPT_DIR/android-run-daemon-signal-boundary-poc.sh" "$@"
