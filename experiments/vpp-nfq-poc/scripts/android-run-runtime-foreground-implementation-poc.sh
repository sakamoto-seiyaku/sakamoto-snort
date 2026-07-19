#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: close SAKAMOTO-18 with a foreground-service implementation smoke.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_ID=21-runtime-foreground-implementation \
  exec bash "$SCRIPT_DIR/android-run-runtime-foreground-smoke-poc.sh" "$@"
