#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
TARGET="${TARGET:-vpp}"
JOBS="${JOBS:-4}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-build-${TARGET}.log"

if [ ! -f "$BUILD_DIR/build.ninja" ]; then
  echo "Android VPP build dir is not configured: $BUILD_DIR" >&2
  echo "Run: make android-vpp-configure-probe" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"

{
  echo "# Android VPP build probe"
  echo "build_dir=$BUILD_DIR"
  echo "target=$TARGET"
  echo "jobs=$JOBS"
  echo

  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0=safe.directory
  export GIT_CONFIG_VALUE_0="$VPP_DIR"

  set +e
  cmake --build "$BUILD_DIR" --target "$TARGET" -j "$JOBS"
  rc=$?
  set -e

  echo
  echo "build_rc=$rc"
  exit "$rc"
} 2>&1 | tee "$LOG"
