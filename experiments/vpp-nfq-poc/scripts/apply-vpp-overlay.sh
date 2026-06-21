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

cp -R --no-preserve=ownership,timestamps "$OVERLAY_DIR/src/." "$VPP_DIR/src/"

echo "Applied overlay to $VPP_DIR"
