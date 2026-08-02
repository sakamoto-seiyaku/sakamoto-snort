#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
OVERLAY_DIR="${OVERLAY_DIR:-$POC_DIR/overlay}"

if [ ! -d "$VPP_DIR/src" ]; then
  echo "VPP source tree not found: $VPP_DIR" >&2
  exit 1
fi

if [ ! -w "$VPP_DIR/src/plugins/nfqueue_poc/CMakeLists.txt" ] &&
  [ "${INSIDE_VPP_NFQ_CONTAINER:-0}" != "1" ]; then
  exec "$SCRIPT_DIR/run-container.sh" env INSIDE_VPP_NFQ_CONTAINER=1 ./scripts/apply-vpp-overlay.sh
fi

cp -R --no-preserve=ownership,timestamps "$OVERLAY_DIR/src/." "$VPP_DIR/src/"

if [ "${SKIP_CORE_PATCHES:-0}" != "1" ]; then
  for overlay_patch in "$OVERLAY_DIR"/patches/*.patch; do
    [ -e "$overlay_patch" ] || continue
    if git -C "$VPP_DIR" apply --check "$overlay_patch" 2>/dev/null; then
      git -C "$VPP_DIR" apply "$overlay_patch"
    elif git -C "$VPP_DIR" apply --reverse --check "$overlay_patch" 2>/dev/null; then
      : # Already applied.
    else
      echo "Overlay patch does not apply cleanly: $overlay_patch" >&2
      exit 1
    fi
  done
else
  echo "Skipped overlay core patches by explicit request"
fi

echo "Applied overlay to $VPP_DIR"
