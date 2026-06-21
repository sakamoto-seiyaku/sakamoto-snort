#!/usr/bin/env bash
set -euo pipefail

VPP_REPO="${VPP_REPO:-https://github.com/FDio/vpp.git}"
VPP_TAG="${VPP_TAG:-v26.02}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"

mkdir -p "$VPP_WORK_ROOT"

if [ -d "$VPP_DIR/.git" ]; then
  echo "VPP tree already exists: $VPP_DIR"
  git -C "$VPP_DIR" fetch --tags --depth 1 origin "$VPP_TAG"
else
  git clone --depth 1 --branch "$VPP_TAG" "$VPP_REPO" "$VPP_DIR"
fi

git -C "$VPP_DIR" checkout "$VPP_TAG"

echo "VPP_DIR=$VPP_DIR"
git -C "$VPP_DIR" rev-parse --short HEAD
git -C "$VPP_DIR" status --short
