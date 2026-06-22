#!/usr/bin/env bash
set -euo pipefail

HEV_REPO="${HEV_REPO:-https://github.com/heiher/hev-socks5-tunnel.git}"
HEV_REF="${HEV_REF:-3911f79}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
HEV_DIR="${HEV_DIR:-$VPP_WORK_ROOT/hev-socks5-tunnel}"

mkdir -p "$VPP_WORK_ROOT"

if [ -d "$HEV_DIR/.git" ]; then
  echo "HEV tree already exists: $HEV_DIR"
  git -C "$HEV_DIR" fetch --tags --prune origin
else
  git clone --recursive "$HEV_REPO" "$HEV_DIR"
fi

git -C "$HEV_DIR" checkout "$HEV_REF"
git -C "$HEV_DIR" submodule update --init --recursive

echo "HEV_DIR=$HEV_DIR"
git -C "$HEV_DIR" describe --tags --always --dirty
git -C "$HEV_DIR" rev-parse --short HEAD
git -C "$HEV_DIR" status --short
