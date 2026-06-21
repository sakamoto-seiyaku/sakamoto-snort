#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_TAG="${VPP_TAG:-v26.02}"
VPP_BUILD_TARGET="${VPP_BUILD_TARGET:-build-release}"
VPP_INSTALL_DEPS="${VPP_INSTALL_DEPS:-0}"
JOBS="${JOBS:-$(nproc)}"

if [ ! -d "$VPP_DIR/.git" ]; then
  "$SCRIPT_DIR/fetch-vpp.sh"
fi

git -C "$VPP_DIR" checkout "$VPP_TAG"

if [ "$VPP_INSTALL_DEPS" = "1" ]; then
  DEBIAN_FRONTEND=noninteractive make -C "$VPP_DIR" UNATTENDED=y install-dep
fi

echo "Building VPP target=$VPP_BUILD_TARGET jobs=$JOBS dir=$VPP_DIR"
make -C "$VPP_DIR" "$VPP_BUILD_TARGET" -j "$JOBS"

echo "VPP build completed"
