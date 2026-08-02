#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
JOBS="${JOBS:-$(nproc)}"

if [ ! -f "$VPP_DIR/build-root/build-vpp-native/vpp/build.ninja" ]; then
  echo "VPP build tree is not configured: $VPP_DIR" >&2
  echo "Run make build-vpp once before the handoff performance POC." >&2
  exit 1
fi

if [ "${INSIDE_VPP_HANDOFF_CONTAINER:-0}" != "1" ]; then
  exec "$SCRIPT_DIR/run-container.sh" env INSIDE_VPP_HANDOFF_CONTAINER=1 \
    JOBS="$JOBS" ./scripts/build-vpp-handoff-perf.sh
fi

# The overlay changes VLIB core state and inline thread APIs, so a plugin-only
# build is insufficient. The normal release target incrementally rebuilds all
# ABI consumers and refreshes the install tree used by the harness.
make -C "$VPP_DIR" MAKE_PARALLEL_JOBS="$JOBS" build-release
